#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_hello_world(struct xdp_md *ctx) {
    bpf_printk("XDP program received a packet\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";