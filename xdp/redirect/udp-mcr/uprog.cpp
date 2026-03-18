#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <iostream>
#include <sstream>

#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <bpf/bpf.h>          // BPF system calls (bpf_obj_get)
#include <xdp/xsk.h>          // AF_XDP socket API (libxdp)
#include <net/if.h>           // Network interface functions (if_nametoindex)
#include <linux/if_link.h>    // XDP constants (XDP_FLAGS_*)

#include "udpp_mcr.c"

/* ============= CONFIGURATION SECTION ============= */

// Frame size: 4096 bytes (4KB) - standard page size, must be power of two
// This is the size of each buffer in UMEM where packets will be stored
static constexpr size_t FRAME_SZ = 4096;

// Ring size: 4096 descriptors - number of buffers in each ring queue
// Larger rings = higher throughput but more memory usage
static constexpr size_t RING_SZ  = 4096;

/**
 * @brief Convert hexadecimal string to raw bytes
 * 
 * @param hexKey Input hex string (e.g., "a1b2c3")
 * @return std::string Raw byte string
 * @throw std::invalid_argument If hex string length is not even
 */
std::string HexToBytes(std::string_view hexKey) {
    if (hexKey.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    
    std::string result;
    result.reserve(hexKey.length() / 2);
    
    for (size_t i = 0; i < hexKey.length(); i += 2) {
        std::string byteStr(hexKey.substr(i, 2));
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << byteStr;
        ss >> byte;
        result.push_back(static_cast<char>(byte));
    }
    
    return result;
}

/**
 * @brief Process an incoming network packet
 * 
 * Parses Ethernet, IP, and UDP headers, validates packet integrity,
 * and calls udp_mcr_entry() for MCR protocol processing.
 * 
 * @param pkt Pointer to packet data in UMEM
 * @param len Length of the packet in bytes
 * @param secret_key Secret key for MCR challenge (raw bytes)
 */
void ProcessIngressPacket(void* pkt, int len, std::string_view secret_key) {
    printf("\n=== Recevied a packet(%d bytes)===\n", len);
    
    void* data_end = (uint8_t*)pkt + len;
    struct ethhdr *eth = (struct ethhdr *)pkt;
    if ((eth + 1) > (struct ethhdr*)data_end) {
        return;
    }
    
    if (eth->h_proto != htons(ETH_P_IP)) {
        printf("Not IP protocol: %d\n", ntohs(eth->h_proto));
        return;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return;
    }
    
    if (ip->protocol != IPPROTO_UDP) {
        printf("Not UDP protocol: %d\n", ip->protocol);
        return;
    }
    
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20) {
        return;
    }
    
    if ((uint8_t*)ip + ip_hdr_len > data_end) {
        return;
    }
    
    struct udphdr *udp = (struct udphdr *)((uint8_t*)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end) {
        return;
    }

    uint8_t *udp_payload = (uint8_t*)udp + sizeof(struct udphdr);
    if (udp_payload >= data_end) {
        printf("No UDP payload\n");
        return;
    }
    udp_mcr_entry(
        eth, ip, udp, (uint8_t*)udp_payload, (uint8_t*)data_end, 
        (uint8_t*)secret_key.data(), secret_key.size()
    );
}

/**
 * @brief Process received packets from the RX ring
 * 
 * This function handles the core packet processing logic:
 * - Retrieves packet descriptors from RX ring
 * - Processes each packet via ProcessIngressPacket()
 * - Optionally queues packets for transmission
 * - Recycles buffers back to Fill Queue
 * 
 * @param rx_packets Number of packets received in this batch
 * @param rxq RX ring consumer queue (packets from kernel)
 * @param rx_idx Index in RX ring to start processing from
 * @param fq Fill ring producer queue (empty buffers to kernel)
 * @param fq_idx Index in Fill ring
 * @param txq TX ring producer queue (packets to transmit)
 * @param umem_area Pointer to UMEM memory region
 * @param secretKey Secret key for MCR processing
 * @return int Number of packets queued for transmission
 */
int ProcessRX(
    uint32_t rx_packets, 
    struct xsk_ring_cons& rxq,
    uint32_t& rx_idx,
    struct xsk_ring_prod& fq,
    uint32_t& fq_idx,
    struct xsk_ring_prod& txq,
    void *umem_area,
    std::string_view secretKey
) {
    // Counter for received packets
    int tx_count = 0;

    /* 6.2 Process each received packet */
    for (uint32_t i = 0; i < rx_packets; i++) {
        // Get packet descriptor (address and length)
        uint64_t addr = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->len;
        
        void *pkt = xsk_umem__get_data(umem_area, addr);
        
        ProcessIngressPacket(pkt, len, secretKey);
        
        uint32_t tx_idx = 0;
        if (xsk_ring_prod__reserve(&txq, 1, &tx_idx) == 1) {
            struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&txq, tx_idx);
            tx_desc->addr = addr;
            tx_desc->len = len;
            
            xsk_ring_prod__submit(&txq, 1);
            ++tx_count;
        } else {
            *xsk_ring_prod__fill_addr(&fq, fq_idx++) = addr;
        }
    }
    
    /* 6.4 Release packets from RX queue
     * - Marks descriptors as processed
     * - Makes room for new packets in RX ring
     */
    xsk_ring_cons__release(&rxq, rx_packets);
    
    /* 6.5 Recycle buffers back to Fill Queue
     * - Get the same buffers we just processed
     * - Add them back to Fill Queue for reuse
     * - This is CRITICAL: kernel needs empty buffers to continue
     */
    uint32_t filled = xsk_ring_prod__reserve(&fq, rx_packets, &fq_idx);
    for (uint32_t i = 0; i < filled; i++) {
        *xsk_ring_prod__fill_addr(&fq, fq_idx + i) = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
    }
    xsk_ring_prod__submit(&fq, filled);

    return tx_count;
}

/**
 * @brief Process TX completions and recycle buffers
 * 
 * Handles packets that have been successfully transmitted:
 * - Checks Completion Queue for finished transmissions
 * - Returns transmitted buffers to Fill Queue for reuse
 * 
 * @param cq Completion queue consumer (TX completions from kernel)
 * @param fq Fill queue producer (empty buffers to kernel)
 * 
 * @note Without processing TX completions, transmitted buffers would
 *       leak and eventually exhaust the UMEM pool.
 */
void ProcessTX(struct xsk_ring_cons& cq, struct xsk_ring_prod& fq) {
    uint32_t cq_idx = 0;
    uint32_t completed = xsk_ring_cons__peek(&cq, 64, &cq_idx);
    
    if (completed > 0) {
        /// Return transmitted buffers to Fill Queue
        uint32_t fill_reserved = xsk_ring_prod__reserve(&fq, completed, &cq_idx);
        for (uint32_t i = 0; i < fill_reserved; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&cq, cq_idx + i);
            *xsk_ring_prod__fill_addr(&fq, cq_idx + i) = addr;
        }
        xsk_ring_prod__submit(&fq, fill_reserved);
        xsk_ring_cons__release(&cq, completed);
    }
}

/**
 * @brief Display program usage information
 * 
 * @param programName Name of the executable (argv[0])
 */
void Usage(std::string_view programName) {
    std::cerr << "Usage: " << programName << " --iface <interface> --queue-id <queue_id>\n"
              << "\nOptions:\n"
              << "  --iface <name>     Interface name (e.g., eth0, lo, ens3)\n"
              << "  --queue-id <num>   RX queue index (0 to num_queues-1)\n"
              << "  --key <str>        Secket key for mcr challenge in hex format\n"
              << "\nExamples:\n"
              << "  " << programName << " --iface eth0 --queue-id 0\n"
              << "  " << programName << " --iface lo --queue-id 0\n";
}

/**
 * @brief Main entry point for AF_XDP packet receiver
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return int Exit status (0 on success, non-zero on error)
 * 
 * @par Program Flow:
 * 1. Parse command line arguments
 * 2. Allocate UMEM (User Memory) region
 * 3. Create UMEM object with Fill and Completion rings
 * 4. Create AF_XDP socket bound to interface/queue
 * 5. Register socket in XSKMAP for eBPF redirection
 * 6. Initialize Fill Queue with empty buffers
 * 7. Enter main packet processing loop
 * 
 * @par AF_XDP Ring Queues:
 * - **Fill Queue (FQ)**: User → Kernel - Provides empty buffers for packet reception
 * - **Completion Queue (CQ)**: Kernel → User - Reports completed transmissions
 * - **RX Queue**: Kernel → User - Delivers received packets
 * - **TX Queue**: User → Kernel - Queues packets for transmission
 * 
 * @par Critical Steps:
 * 1. UMEM allocation must be page-aligned
 * 2. XSKMAP registration is required for eBPF redirection
 * 3. Fill Queue must be initially populated with buffers
 * 4. Buffers must be continuously recycled
 * 
 * @par Performance Considerations:
 * - Use XDP_ZEROCOPY for real NICs (higher performance)
 * - Use XDP_COPY for loopback/virtual interfaces
 * - Adjust ring sizes based on traffic patterns
 * - Consider using poll() instead of sleep for better efficiency
 */
int main(int argc, char** argv) {
    assert(argc > 0);
    std::string_view program{argv[0]};

    if (argc <=  1) {
        Usage(program);
        return EXIT_SUCCESS;
    }

    // Interface name: "lo" - loopback interface for testing
    // Change to "eth0", "ens3", etc. for physical interfaces
    std::string iface;

    // Secret key for MCR challenge in hex format
    std::string key;

    // Queue ID: 0 - RX queue index to bind to
    // For physical NICs: 0 to (num_queues-1), for loopback always 0
    int queueId = -1;

    for (auto i = 1; i < argc; ) {
        std::string_view arg{argv[i]};

        if (arg == "--iface" && i + 1 < argc) {
            iface = argv[i + 1];
            i += 2;
        }  else if (arg == "--queue" && i + 1 < argc) {
            queueId = std::stoi(argv[i + 1]);
            i += 2;
        } else if (arg == "--key" && i + 1 < argc) {
            key = HexToBytes(argv[i + 1]);
            i += 2;
        }else if (arg == "--help" || arg == "-h") {
            Usage(program);
            return EXIT_SUCCESS;
        } else {
            std::cerr << "Error: Unknown argument: " << arg << "\n";
            Usage(program);
            return EXIT_FAILURE;
        }
    }

    if (iface.empty()) {
        std::cerr << "Error: --iface is required\n";
        Usage(program);
        return EXIT_FAILURE;
    }

    if (key.empty()) {
        std::cerr << "Error: --key is required\n";
        Usage(program);
        return EXIT_FAILURE;
    }
    
    if (queueId < 0) {
        std::cerr << "Error: --queue-id is required and must be >= 0\n";
        Usage(program);
        return EXIT_FAILURE;
    }
    
    // UMEM (User Memory) area - pre-allocated buffer pool for packets
    void *umem_area = nullptr;
    
    // libxdp handles for UMEM and socket
    struct xsk_umem *umem = nullptr;      // UMEM object
    struct xsk_socket *xsk = nullptr;     // AF_XDP socket
    
    // Four ring queues required for AF_XDP:
    struct xsk_ring_prod fq;    // FILL queue: user → kernel (give empty buffers)
    struct xsk_ring_cons cq;    // COMPLETION queue: kernel → user (TX completed)
    struct xsk_ring_cons rxq;   // RX queue: kernel → user (incoming packets)
    struct xsk_ring_prod txq;   // TX queue: user → kernel (outgoing packets)
    
    int ret = 0;
    int xsks_map_fd = 0;
    uint32_t idx = 0;
    
    
    printf("=== AF_XDP Packet Receiver ===\n");
    printf("Interface: %s, secret-key: %s, Queue: %d\n\n", iface.data(), key.data(), queueId);
    
    // ===== UMEM ALLOCATION AND SETUP =====
    
    //Allocate UMEM area (page-aligned memory)
    umem_area = aligned_alloc(4096, FRAME_SZ * RING_SZ);
    if (!umem_area) {
        perror("aligned_alloc failed");
        return 1;
    }
    printf("[1] UMEM allocated: %lu bytes\n", 
           (unsigned long)(FRAME_SZ * RING_SZ));
    
    /* Create UMEM object
     * - Registers the memory area with the kernel
     * - Creates Fill and Completion ring buffers
     * - UMEM configuration:
     *   - fill_size: Size of Fill ring (how many buffers we give to kernel)
     *   - comp_size: Size of Completion ring (TX completed buffers)
     *   - frame_size: Size of each buffer (must match FRAME_SZ)
     *   - frame_headroom: Optional space before packet data (0 for simplicity)
     */
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SZ,       // Fill ring size
        .comp_size = RING_SZ,       // Completion ring size  
        .frame_size = FRAME_SZ,     // Buffer size
        .frame_headroom = 0,        // No extra headroom
        .flags = 0                  // No special flags
    };
    
    ret = xsk_umem__create(&umem, umem_area, FRAME_SZ * RING_SZ, 
                          &fq, &cq, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %d\n", ret);
        throw std::runtime_error{"xsk_umem__create failed"};
    }
    printf("[2] UMEM created successfully\n");
    
    // ===== AF_XDP SOCKET CREATION =====
    
    /* Create AF_XDP socket
     * - Binds to specific interface (IFNAME) and RX queue (QUEUE_ID)
     * - Shares UMEM with the kernel
     * - Creates RX and TX ring buffers
     */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = RING_SZ,
        .tx_size = RING_SZ,
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, // Don't load default eBPF
        .xdp_flags = XDP_FLAGS_SKB_MODE,     // Generic/SKB mode (works everywhere)
        .bind_flags = XDP_COPY,              // XDP_COPY mode for loopback/veth-pair. For real interface may use XDP_ZEROCOPY
    };
    
    ret = xsk_socket__create_shared(&xsk, iface.data(), queueId,
                                    umem, &rxq, &txq, &fq, &cq, &xsk_cfg);
    if (ret) {
        throw std::runtime_error{"Could not create AF_XDP socket: " + std::string{strerror(errno)}};
    }
    printf("[3] AF_XDP socket created, fd=%d\n", xsk_socket__fd(xsk));
    
    // ===== REGISTER SOCKET IN XSKMAP (CRITICAL STEP) =====
    
    /* Get file descriptor for XSKMAP
     * - XSKMAP is a BPF map of type BPF_MAP_TYPE_XSKMAP
     * - It stores AF_XDP socket FDs keyed by queue index
     * - eBPF program looks up sockets in this map for redirection
     * - Map is pinned at /sys/fs/bpf/xsks_map by our eBPF loader
     */
    xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map_fd < 0) {
        perror("bpf_obj_get(/sys/fs/bpf/xsks_map)");
        fprintf(stderr, "Ensure eBPF program is loaded: make load\n");
        throw std::runtime_error{"Get file descriptor failed: " + std::string{strerror(errno)}};
    }
    
    /* Register socket in XSKMAP
     * - xsk_socket__update_xskmap() is the CORRECT way to add socket to map
     * - Previously used bpf_map_update_elem() may silently fail
     * - This is the MOST COMMON source of problems in AF_XDP setups
     * - After this call, eBPF program can redirect packets to our socket
     */
    ret = xsk_socket__update_xskmap(xsk, xsks_map_fd);
    if (ret) {
        fprintf(stderr, "xsk_socket__update_xskmap failed: %d\n", ret);
        fprintf(stderr, "This is the most frequent cause of AF_XDP issues!\n");
        throw std::runtime_error{"Register socket in XSKMAP failed: " + std::string{strerror(errno)}};
    }
    printf("[4] Socket registered in xsks_map[%d]\n", queueId);
    
    // ===== FILL QUEUE INITIALIZATION =====
    
    /* Reserve descriptors in Fill Queue
     * - Fill Queue is where we give empty buffers to the kernel
     * - Kernel uses these buffers to store incoming packets
     * - We try to reserve ALL descriptors (RING_SZ) at once
     */
    uint32_t n = xsk_ring_prod__reserve(&fq, RING_SZ, &idx);
    if (n != RING_SZ) {
        fprintf(stderr, "Could only reserve %u of %lu FQ descriptors\n", 
                n, (unsigned long)RING_SZ);
        throw std::runtime_error{"FILL QUEUE INITIALIZATION failed: " + std::string{strerror(errno)}};
    }
    
    /* Fill with buffer addresses
     * - Each descriptor gets an offset into UMEM area
     * - Address = i * FRAME_SZ (linear mapping)
     * - Kernel will write packets starting at these addresses
     */
    for (uint32_t i = 0; i < n; i++) {
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SZ;
    }
    
    /* Submit descriptors to kernel
     * - Makes buffers available for kernel to use
     * - After this, kernel can receive packets into our UMEM
     */
    xsk_ring_prod__submit(&fq, n);
    printf("[5] Fill Queue filled with %u buffers\n", n);
    printf("\n[READY] Waiting for packets (send ping to %s)...\n", iface.data());
    
    // ===== MAIN PACKET PROCESSING LOOP =====
    while (true) {
        uint32_t rx_idx = 0, fq_idx = 0;
        ProcessTX(cq, fq);
        /* Check for received packets
         * - xsk_ring_cons__peek() checks RX queue without removing
         * - Returns number of available packets (up to 64 in this batch)
         * - rx_idx is set to starting index in RX ring
         */
        uint32_t rx_packets = xsk_ring_cons__peek(&rxq, 64, &rx_idx);
        if (rx_packets > 0) {
            int tx = ProcessRX(rx_packets, rxq, rx_idx, fq, fq_idx, txq, umem_area, key);

            // Будим TX если есть что отправлять
            if (tx > 0) {
                sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            }
        } else {
            /* No packets available - sleep briefly
             * - Avoids busy-waiting consuming 100% CPU
             * - 1ms sleep is reasonable for interactive testing
             * - For high-performance: use poll() or busy-poll with needs_wakeup
             */
            usleep(1000); // Sleep for 1 millisecond
        }
    }
    return 0;
}