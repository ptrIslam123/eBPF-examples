// egress.c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    bpf_printk("tc/egress");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";