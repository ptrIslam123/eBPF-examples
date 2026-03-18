#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/types.h>

#define CHECK_BOUNDS(ptr, size) \
    if ((void *)(ptr) + (size) > data_end) \
        return XDP_PASS;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} packet_stat SEC(".maps");

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

    // Update packet statistics
    __u32 key = ip->protocol;
    __u64* value = bpf_map_lookup_elem(&packet_stat, &key);
    if (value) {
        __u64 new_value = *value + 1;
        bpf_map_update_elem(&packet_stat, &key, &new_value, BPF_EXIST);
    } else {
        __u64 count = 1;
        bpf_map_update_elem(&packet_stat, &key, &count, BPF_ANY);
    }
    bpf_printk("add a package into stat map\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";