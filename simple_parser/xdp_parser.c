#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define CHECK_BOUNDS(ptr, size) \
    if ((void *)(ptr) + (size) > data_end) \
        return XDP_PASS;

SEC("xdp")
int xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet-header
    struct ethhdr *eth = (struct ethhdr*)data;
    CHECK_BOUNDS(eth, sizeof(*eth));

    // Pass non-IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parser IP-header
    struct iphdr *ip = data + sizeof(*eth);
    CHECK_BOUNDS(ip, sizeof(*ip))
    
    // Only IPv4
    if (ip->version != 4 || ip->ihl < 5)
        return XDP_PASS;

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = data + sizeof(*eth) + (ip->ihl * 4);
            CHECK_BOUNDS(tcp, sizeof(*tcp))
            bpf_printk("[TCP] package\n");
            return XDP_PASS;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = data + sizeof(*eth) + (ip->ihl * 4);
            CHECK_BOUNDS(udp, sizeof(*udp))
            bpf_printk("[UDP] package\n");   
            return XDP_PASS;
        }
        default: {
            bpf_printk("[Unknown] package\n");
            return XDP_PASS;
        } 
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";