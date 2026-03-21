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

// License declaration - mandatory for eBPF programs
// Kernel verifier checks this to ensure GPL compatibility
char LICENSE[] SEC("license") = "GPL";

/*
0       7 8      15 16    23 24    31
+--------+--------+--------+--------+
|          source address           |  4 bytes (2 word)
+--------+--------+--------+--------+
|        destination address        |  4 bytes (2 word)
+--------+--------+--------+--------+
|  zero  | protocol|    UDP length  |  4 bytes (2 word)
+--------+--------+--------+--------+
  1 bytes   1 bytes      2 bytes
*/
struct ipv4_pseudo_header {
    __be32 saddr;      // source IP address (4 bytes)
    __be32 daddr;      // destination IP address (4 bytes)
    __u8   zero;       // zero (1 byte)
    __u8   protocol;   // protocol (1 byte)
    __be16 udp_len;    // UDP length (2 bytes)
} __attribute__((packed));


// XDP (eXpress Data Path) program section
// This function is called for every packet received on the interface
SEC("xdp")
int xdp_redirect_all(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
        
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;
        
    struct udphdr *udp = (struct udphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    __u8* payload = (__u8*)udp + sizeof(struct udphdr);
    __u8* payload_end = (__u8*)data_end;
    if (payload > payload_end) {
        return XDP_PASS;
    }

    __u16 udp_len = 11;
    udp->len = bpf_htons(sizeof(struct udphdr) + udp_len);
    if (payload + udp_len > payload_end) {
        return XDP_PASS;
    }

    swap_mac(eth);
    swap_ip(ip);
    swap_udp_ports(udp);

    // --- Full recalculate UDP CHECKSUM ---
    __wsum csum = 0;
    udp->check = 0;

    struct ipv4_pseudo_header pseudo_hdr = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .zero = 0,
        .protocol = IPPROTO_UDP,
        .udp_len = bpf_htons(udp_len + sizeof(struct udphdr)),
    };
    csum = bpf_csum_diff(NULL, 0, (__be32 *)&pseudo_hdr, sizeof(pseudo_hdr), csum);
    csum = bpf_csum_diff(NULL, 0, (__be32 *)udp, sizeof(struct udphdr) + udp_len, csum);

    __u32 result = (csum & 0xffff) + (csum >> 16);
    result = (result & 0xffff) + (result >> 16);
    result = ~result;

    udp->check = (result == 0) ? 0xFFFF : (__u16)result;
    
    bpf_printk("UDP packet modified, new checksum=0x%x\n", udp->check);
    return XDP_TX;
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
