/* 
 * AF_XDP Packet Receiver - Minimal Working Example
 * 
 * This program demonstrates how to receive packets from XDP eBPF program
 * via AF_XDP sockets. It creates a userspace packet receiver that:
 * 1. Allocates UMEM (User Memory) for packet buffers
 * 2. Creates an AF_XDP socket bound to a specific interface and queue
 * 3. Registers the socket in XSKMAP for XDP redirection
 * 4. Receives and displays incoming packets
 */

#include <cassert>
#include <string>
#include <string_view>
#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <bpf/bpf.h>          // BPF system calls (bpf_obj_get)
#include <xdp/xsk.h>          // AF_XDP socket API (libxdp)
#include <net/if.h>           // Network interface functions (if_nametoindex)
#include <linux/if_link.h>    // XDP constants (XDP_FLAGS_*, XDP_COPY)

/* ============= CONFIGURATION SECTION ============= */

// Frame size: 4096 bytes (4KB) - standard page size, must be power of two
// This is the size of each buffer in UMEM where packets will be stored
static constexpr size_t FRAME_SZ = 4096;

// Ring size: 4096 descriptors - number of buffers in each ring queue
// Larger rings = higher throughput but more memory usage
static constexpr size_t RING_SZ  = 4096;

// Process redirected packages from the bpf program
void ProcessRedirectedPackets(
    uint32_t rx_packets, 
    struct xsk_ring_cons& rxq,
    uint32_t& rx_idx,
    struct xsk_ring_prod& fq,
    uint32_t& fq_idx
) {
    // Counter for received packets
    static int packet_count = 0;

    /* 6.2 Process each received packet */
    for (uint32_t i = 0; i < rx_packets; i++) {
        // Get packet descriptor (address and length)
        uint64_t addr = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->len;
        
        packet_count++;
        printf("[PACKET #%d] %u bytes | Addr: 0x%lx\n", 
                packet_count, len, (unsigned long)addr);
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
        *xsk_ring_prod__fill_addr(&fq, fq_idx + i) = 
            xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
    }
    xsk_ring_prod__submit(&fq, filled);
}

void Usage(std::string_view programName) {
    std::cerr << "Usage: " << programName << " --iface <interface> --queue-id <queue_id>\n"
              << "\nOptions:\n"
              << "  --iface <name>     Interface name (e.g., eth0, lo, ens3)\n"
              << "  --queue-id <num>   RX queue index (0 to num_queues-1)\n"
              << "\nExamples:\n"
              << "  " << programName << " --iface eth0 --queue-id 0\n"
              << "  " << programName << " --iface lo --queue-id 0\n";
}

/* ============= MAIN FUNCTION ============= */
int main(int argc, char** argv) {
    assert(argc > 0);
    std::string_view program{argv[0]};

    if (argc <=  1) {
        Usage(program);
        return EXIT_SUCCESS;
    }

    // Interface name: "lo" - loopback interface for testing
    // Change to "eth0", "ens3", etc. for physical interfaces
    std::string_view iface;

    // Queue ID: 0 - RX queue index to bind to
    // For physical NICs: 0 to (num_queues-1), for loopback always 0
    int queueId = -1;

    for (auto i = 1; i < argc; ) {
        std::string_view arg{argv[i]};

        if (arg == "--iface" && i + 1 < argc) {
            iface = argv[i + 1];
            i += 2;
        } 
        else if (arg == "--queue" && i + 1 < argc) {
            queueId = std::stoi(argv[i + 1]);
            i += 2;
        } else if (arg == "--help" || arg == "-h") {
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
    
    if (queueId < 0) {
        std::cerr << "Error: --queue-id is required and must be >= 0\n";
        Usage(program);
        return EXIT_FAILURE;
    }

    // ===== PHASE 1: VARIABLE DECLARATIONS =====
    // All variables declared at the beginning (C++ scope rules with throw)
    
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
    
    // Misc variables
    int ret = 0;                // Return code from libxdp functions
    int xsks_map_fd = 0;        // File descriptor for XSKMAP BPF map
    uint32_t idx = 0;           // Index in ring buffer
    
    
    printf("=== AF_XDP Packet Receiver ===\n");
    printf("Interface: %s, Queue: %d\n\n", iface.data(), queueId);
    
    // ===== PHASE 2: UMEM ALLOCATION AND SETUP =====
    
    /* 2.1 Allocate UMEM area (page-aligned memory)
     * - aligned_alloc(4096, ...) ensures 4KB alignment (required by most NICs)
     * - Size = FRAME_SZ * RING_SZ (e.g., 4096 * 4096 = 16MB)
     * - This memory will be shared between userspace and kernel
     */
    umem_area = aligned_alloc(4096, FRAME_SZ * RING_SZ);
    if (!umem_area) {
        perror("aligned_alloc failed");
        return 1;
    }
    printf("[1] UMEM allocated: %lu bytes\n", 
           (unsigned long)(FRAME_SZ * RING_SZ));
    
    /* 2.2 Create UMEM object
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
        throw 1;  // Using throw for cleanup (C++ style)
    }
    printf("[2] UMEM created successfully\n");
    
    // ===== PHASE 3: AF_XDP SOCKET CREATION =====
    
    /* 3.1 Create AF_XDP socket
     * - Binds to specific interface (IFNAME) and RX queue (QUEUE_ID)
     * - Shares UMEM with the kernel
     * - Creates RX and TX ring buffers
     * 
     * Socket configuration:
     * - rx_size/tx_size: Ring sizes for RX/TX (must be power of 2)
     * - libxdp_flags: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (we use our own eBPF)
     * - xdp_flags: XDP_FLAGS_SKB_MODE (generic mode, works on all interfaces)
     * - bind_flags: XDP_COPY (CRITICAL for loopback - copies packets to UMEM)
     * 
     * NOTE: For physical NICs with driver support, you might use:
     *   - xdp_flags: XDP_FLAGS_DRV_MODE (for zero-copy)
     *   - bind_flags: 0 (for zero-copy mode)
     */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = RING_SZ,          // RX ring size
        .tx_size = RING_SZ,          // TX ring size
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, // Don't load default eBPF
        .xdp_flags = XDP_FLAGS_SKB_MODE,     // Generic/SKB mode (works everywhere)
        .bind_flags = XDP_COPY,              // COPY mode for loopback
    };
    
    ret = xsk_socket__create_shared(&xsk, iface.data(), queueId,
                                    umem, &rxq, &txq, &fq, &cq, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create_shared failed: %d\n", ret);
        fprintf(stderr, "Possible reasons:\n");
        fprintf(stderr, "1. Interface %s doesn't support XDP\n", iface.data());
        fprintf(stderr, "2. XDP_COPY flag not set for loopback\n");
        fprintf(stderr, "3. eBPF program not loaded on interface\n");
        throw 1;
    }
    printf("[3] AF_XDP socket created, fd=%d\n", xsk_socket__fd(xsk));
    
    // ===== PHASE 4: REGISTER SOCKET IN XSKMAP (CRITICAL STEP) =====
    
    /* 4.1 Get file descriptor for XSKMAP
     * - XSKMAP is a BPF map of type BPF_MAP_TYPE_XSKMAP
     * - It stores AF_XDP socket FDs keyed by queue index
     * - eBPF program looks up sockets in this map for redirection
     * - Map is pinned at /sys/fs/bpf/xsks_map by our eBPF loader
     */
    xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map_fd < 0) {
        perror("bpf_obj_get(/sys/fs/bpf/xsks_map)");
        fprintf(stderr, "Ensure eBPF program is loaded: make load\n");
        throw 1;
    }
    
    /* 4.2 Register socket in XSKMAP
     * - xsk_socket__update_xskmap() is the CORRECT way to add socket to map
     * - Previously used bpf_map_update_elem() may silently fail
     * - This is the MOST COMMON source of problems in AF_XDP setups
     * - After this call, eBPF program can redirect packets to our socket
     */
    ret = xsk_socket__update_xskmap(xsk, xsks_map_fd);
    if (ret) {
        fprintf(stderr, "xsk_socket__update_xskmap failed: %d\n", ret);
        fprintf(stderr, "This is the most frequent cause of AF_XDP issues!\n");
        throw 1;
    }
    printf("[4] Socket registered in xsks_map[%d]\n", queueId);
    
    // ===== PHASE 5: FILL QUEUE INITIALIZATION =====
    
    /* 5.1 Reserve descriptors in Fill Queue
     * - Fill Queue is where we give empty buffers to the kernel
     * - Kernel uses these buffers to store incoming packets
     * - We try to reserve ALL descriptors (RING_SZ) at once
     */
    uint32_t n = xsk_ring_prod__reserve(&fq, RING_SZ, &idx);
    if (n != RING_SZ) {
        fprintf(stderr, "Could only reserve %u of %lu FQ descriptors\n", 
                n, (unsigned long)RING_SZ);
        throw 1;
    }
    
    /* 5.2 Fill with buffer addresses
     * - Each descriptor gets an offset into UMEM area
     * - Address = i * FRAME_SZ (linear mapping)
     * - Kernel will write packets starting at these addresses
     */
    for (uint32_t i = 0; i < n; i++) {
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SZ;
    }
    
    /* 5.3 Submit descriptors to kernel
     * - Makes buffers available for kernel to use
     * - After this, kernel can receive packets into our UMEM
     */
    xsk_ring_prod__submit(&fq, n);
    printf("[5] Fill Queue filled with %u buffers\n", n);
    printf("\n[READY] Waiting for packets (send ping to %s)...\n", iface.data());
    
    // ===== PHASE 6: MAIN PACKET PROCESSING LOOP =====
    
    while (1) {
        uint32_t rx_idx = 0, fq_idx = 0;
        
        /* 6.1 Check for received packets
         * - xsk_ring_cons__peek() checks RX queue without removing
         * - Returns number of available packets (up to 64 in this batch)
         * - rx_idx is set to starting index in RX ring
         */
        uint32_t rx_packets = xsk_ring_cons__peek(&rxq, 64, &rx_idx);
        if (rx_packets > 0) {
            ProcessRedirectedPackets(rx_packets, rxq, rx_idx, fq, fq_idx);
        } else {
            /* 6.6 No packets available - sleep briefly
             * - Avoids busy-waiting consuming 100% CPU
             * - 1ms sleep is reasonable for interactive testing
             * - For high-performance: use poll() or busy-poll with needs_wakeup
             */
            usleep(1000); // Sleep for 1 millisecond
        }
    }
    
    // Note: In production, you would have proper cleanup code here
    // This example uses throw for error handling, so cleanup would be in catch block
    return 0;
}