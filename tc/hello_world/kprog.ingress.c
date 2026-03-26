// ingress.c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    bpf_printk("tc/ingress");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";