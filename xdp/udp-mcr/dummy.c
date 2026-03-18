#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx) {
    bpf_printk("... received packet to dummy xdp program\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";