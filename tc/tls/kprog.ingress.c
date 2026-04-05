#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tls_handler.h"

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    bpf_printk("tc.ingress");
    return parse_tcp(skb);
}

char _license[] SEC("license") = "GPL";