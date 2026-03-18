#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/types.h>


#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define CHECK_BOUNDS(ptr, size) \
    if ((void *)(ptr) + (size) > data_end) \
        return XDP_PASS;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} ringbuf SEC(".maps");

struct event {
    __u8 protocol;
    __u32 packet_size;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

SEC("xdp")
int xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet-header
    struct ethhdr *eth = (struct ethhdr*)data;
    CHECK_BOUNDS(eth, sizeof(*eth));

    // Pass non-IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parser IP-header
    struct iphdr *ip = data + sizeof(*eth);
    CHECK_BOUNDS(ip, sizeof(*ip))
    
    // Only IPv4
    if (ip->version != 4 || ip->ihl < 5)
        return XDP_PASS;

    struct event e = {};
    e.protocol = ip->protocol;
    e.packet_size = bpf_ntohs(ip->tot_len);
    e.saddr = ip->saddr;
    e.daddr = ip->daddr;

    // Parse Transport
    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = data + sizeof(*eth) + (ip->ihl * 4);
            CHECK_BOUNDS(tcp, sizeof(*tcp))
            e.sport = bpf_ntohs(tcp->source);
            e.dport = bpf_ntohs(tcp->dest);
            bpf_printk("[TCP] package\n");
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = data + sizeof(*eth) + (ip->ihl * 4);
            CHECK_BOUNDS(udp, sizeof(*udp))
            e.sport = bpf_ntohs(udp->source);
            e.dport = bpf_ntohs(udp->dest);
            bpf_printk("[UDP] package\n");   
            break;
        }
        default: {
            bpf_printk("[Unknown] package\n");
            break;
        } 
    }

    // Send event into ring buffer
    bpf_ringbuf_output(&ringbuf, &e, sizeof(e), 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";