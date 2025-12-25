#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>   // XDP_FLAGS_* constants

#include <xdp/xsk.h>         // libxdp structures and functions (AF_XDP)
#include <bpf/bpf.h>         // bpf_obj_get, bpf_map_update_elem

/* ---------- 1. QUEUE AND BUFFER SIZES ---------- */
static constexpr size_t FRAME_SZ = 4096; // Size of ONE buffer in bytes.
                                         // MUST be power of two, ≥ 2 KB,
                                         // usually 4 KB (4096) – universal.
static constexpr size_t RING_SZ  = 4096; // Number of buffers in the ring.
                                         // More = higher peak throughput,
                                         // but more memory and cache misses.
static constexpr int    QUEUE_ID = 0;    // RX queue number of NIC. For lo always 0,
                                         // for physical NIC = 0 .. (queues-1).
static constexpr char   IFNAME[] = "lo"; // Interface where eBPF program
                                         // with XSKMAP section was previously loaded.

/* ---------- 2. UMEM (USER MEMORY) ---------- */
int main()
{
    /* 2.1 Allocate virtual memory for buffer ring.
          aligned_alloc(4096, ...) gives page aligned to 4 KB –
          requirement of most drivers for huge-pages / zero-copy. */
    void *umem_area = aligned_alloc(4096, FRAME_SZ * RING_SZ);
    if (!umem_area) { perror("umem"); return 1; }

    /* 2.2 Describe UMEM parameters. */
    struct xsk_umem_config umem_cfg = {
        .fill_size   = RING_SZ, // How many descriptors in FILL queue (RX)
        .comp_size   = RING_SZ, // How many in COMPLETION queue (TX)
        .frame_size  = FRAME_SZ,// Bytes in one buffer (same as above)
        .frame_headroom = 0,    // Bytes that XSK will leave for
                                // internal structures (can be 0-256).
        .flags       = 0,       // No need for XSK_UMEM_* flags yet.
    };

    /* 2.3 Create UMEM object. Inside:
          - 4 ring buffers are allocated (FQ, CQ, RX, TX);
          - memory is registered in kernel;
          - pointers to rings are returned. */
    struct xsk_ring_prod fq;    // FILL:  user → kernel (buffer addresses for RX)
    struct xsk_ring_cons cq;    // COMP:  kernel → user (addresses freed after TX)
    struct xsk_umem *umem;
    if (xsk_umem__create(&umem, umem_area, FRAME_SZ * RING_SZ, &fq, &cq, &umem_cfg)) {
        fprintf(stderr, "xsk_umem__create failed\n"); 
        return 1;
    }

    /* ---------- 3. CREATING AF_XDP SOCKET ---------- */
    struct xsk_socket_config xsk_cfg = {
        .rx_size      = RING_SZ, // RX ring size (must be power of 2)
        .tx_size      = RING_SZ, // TX ring size
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
                                  // Do NOT load eBPF from libxdp – we already loaded ours
        .xdp_flags    = XDP_FLAGS_SKB_MODE,
                                  // Work in SKB mode (generic, not driver).
                                  // Suitable for any interface, but slower.
        .bind_flags   = 0,       // 0 = RX+TX, XDP_COPY = copy on buffer shortage
    };

    struct xsk_socket *xsk;     // Socket handle
    struct xsk_ring_cons rxq;   // RX: kernel → user (incoming packets)
    struct xsk_ring_prod txq;   // TX: user → kernel (packets to send)

    /* 3.1 Create socket and rings. Arguments:
          iface, queue_id, umem, pointers to 4 rings, config. */
    if (xsk_socket__create_shared(&xsk, IFNAME, QUEUE_ID,
                                  umem, &rxq, &txq, &fq, &cq, &xsk_cfg)) {
        fprintf(stderr, "xsk_socket__create_shared failed\n"); 
        return 1;
    }

    /* ---------- 4. CONNECTING TO BPF-MAP ---------- */
    /* 4.1 Get fd of map file created by eBPF program
          (it pinned it in /sys/fs/bpf/xsks_map). */
    int xsks_map = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map < 0) { 
        fprintf(stderr, "bpf_obj_get failed\n"); 
        return 1; 
    }

    /* 4.2 Take fd of newly created socket and insert into map
          under key = queue number. Now eBPF can redirect
          packets specifically to this socket. */
    int fd = xsk_socket__fd(xsk);
    uint32_t key = QUEUE_ID;
    int ret = bpf_map_update_elem(xsks_map, &key, &fd, BPF_ANY);
    if (ret) {
        fprintf(stderr, "update_elem -> %d (%s)\n", ret, strerror(-ret));
        return 1;
    }
    printf("fd %d inserted -> xsks_map[%u]\n", fd, key);

    /* ---------- 5. FILLING FILL QUEUE ---------- */
    /* 5.1 Take block of descriptors from FILL. */
    uint32_t idx;
    uint32_t n = xsk_ring_prod__reserve(&fq, RING_SZ, &idx);
    /* 5.2 Write address of free buffer to each descriptor. */
    for (uint32_t i = 0; i < n; ++i)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SZ;

    /* 5.3 Publish descriptors – kernel can now write packets. */
    xsk_ring_prod__submit(&fq, n);

    puts("waiting for packets on lo queue 0 …");

    /* ---------- 6. MAIN RECEIVE LOOP ---------- */
    while (true) {
        /* 6.1 Check how many new packets are ready. */
        n = xsk_ring_cons__peek(&rxq, 64, &idx);
        if (!n) { 
            usleep(1); 
            continue; 
        }

        /* 6.2 Process each packet. */
        for (uint32_t i = 0; i < n; ++i) {
            /* get descriptor: address + length */
            auto *desc = xsk_ring_cons__rx_desc(&rxq, idx + i);
            uint8_t *pkt = (uint8_t*)umem_area + (desc->addr & (FRAME_SZ - 1));
            uint32_t len = desc->len;

            /* print first 256 bytes in hex */
            len = len > 256 ? 256 : len;
            printf("[%u B] ", len);
            for (uint32_t j = 0; j < len; ++j)  printf("%02x", pkt[j]);
            puts("");
        }

        /* 6.3 Release descriptors – kernel can overwrite buffers. */
        xsk_ring_cons__release(&rxq, n);

        /* 6.4 Return **the same** buffers to FILL, so kernel can
               receive traffic again. */
        uint32_t cnt = xsk_ring_prod__reserve(&fq, n, &idx);
        for (uint32_t i = 0; i < cnt; ++i)
            *xsk_ring_prod__fill_addr(&fq, idx + i) =
                xsk_ring_cons__rx_desc(&rxq, idx + i)->addr;
        xsk_ring_prod__submit(&fq, cnt);
    }

    /* ---------- 7. CLEANUP ---------- */
    /* In real code should:
       - xsk_socket__delete
       - xsk_umem__delete
       - free(umem_area)
       - delete map pin
       - remove XDP */
    return 0;
}