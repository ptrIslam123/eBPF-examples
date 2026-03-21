#include <linux/bpf.h>      // Basic eBPF definitions and types
#include <linux/if_ether.h> // Ethernet protocol definitions
#include <bpf/bpf_helpers.h> // eBPF helper functions
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "checksum.h"

#include "mcr.c"

// License declaration - mandatory for eBPF programs
// Kernel verifier checks this to ensure GPL compatibility
char LICENSE[] SEC("license") = "GPL";

__u8 secret_key[] = {
    0x12, 0x34, 0x56, 0x78,
    0x12, 0x34, 0x56, 0x78
};

// XDP (eXpress Data Path) program section
// This function is called for every packet received on the interface
SEC("xdp")
int xdp_redirect_all(struct xdp_md *ctx)
{
    // Extract RX queue index from the packet context
    // Each network interface can have multiple RX queues for parallel processing
    __u32 index = (__u32)ctx->rx_queue_index;

    // Safety check: ensure queue index is within map bounds
    // If index >= 64, pass the packet to normal kernel network stack
    if (index >= 64)
        return XDP_PASS;  // Let packet continue through normal network stack

    // Debug output - writes to kernel trace buffer
    // Can be viewed with: sudo cat /sys/kernel/debug/tracing/trace_pipe
    // Note: In production, remove or conditionalize this for performance
    bpf_printk("XDP program received a packet, RX index=%d\n", index);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) {
        bpf_printk("Not udp, protocol=%d\n", ip->protocol);
        return XDP_PASS;
    }

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20) {
        return XDP_PASS;
    }

    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    struct udphdr *udp = (struct udphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS;
    }

    __u8* payload = (__u8*)udp + sizeof(struct udphdr);
    __u8* payload_end = (__u8*)data_end;
    if (payload > payload_end) {
        return XDP_PASS;
    }

    return handle_mcr(eth, ip, udp, payload, payload_end, secret_key, sizeof(secret_key));
}

// How this works with userspace:
// 1. Userspace creates an AF_XDP socket bound to a specific queue
// 2. Userspace inserts socket FD into xsks_map at key = queue index
// 3. When packet arrives on that queue, XDP program redirects it to the socket
// 4. Userspace receives packet via AF_XDP socket, bypassing kernel network stack
//
// Performance benefits:
// - Zero-copy: packets go directly from NIC to userspace
// - Bypasses kernel networking stack
// - Very low latency (microseconds)
//
// Typical use cases:
// - High-performance packet processing
// - DDoS protection
// - Load balancers
// - Network monitoring
//
// Important notes:
// - Program runs in kernel context - must be safe and verifiable
// - Limited to 1 million instructions per packet
// - No loops (except bounded), no blocking operations
// - Must pass kernel verifier checks
