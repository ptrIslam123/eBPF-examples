#pragma once

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline int dump_tcp(__u8* data, __u8* data_end) {
    bpf_printk("packet len=%d", data_end - data);
    
    /* Parse Ethernet */
    struct ethhdr *eth = (struct ethhdr*)data;
    if ((__u8*)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Check for IPv4 (ETH_P_IP) */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    /* Parse IP */
    struct iphdr *ip = (struct iphdr*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Check IP header length */
    __u8 ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20 || (__u8*)ip + ip_header_len > data_end) {
        return TC_ACT_OK;  // Changed from XDP_PASS to TC_ACT_OK
    }

    /* Check protocol */
    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    /* TCP header */
    struct tcphdr *tcp = (struct tcphdr*)((__u8*)ip + ip_header_len);
    if ((__u8*)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Get TCP header length (in bytes) */
    __u8 tcp_header_len = tcp->doff * 4;  // doff is in 32-bit words

    /* Check if tcp_header_len is valid (20-60 bytes) */
    if ((__u8*)tcp + tcp_header_len > data_end || 
        tcp_header_len < sizeof(struct tcphdr) || 
        tcp_header_len > 60) {
        bpf_printk("Invalid TCP header length: %d", tcp_header_len);
        return TC_ACT_OK;
    }

    /* Calculate TCP payload start */
    __u8 *tcp_payload = (__u8*)tcp + tcp_header_len;
    if (tcp_payload > data_end) {
        bpf_printk("TCP options exceed packet");
        return TC_ACT_OK;
    }
    __u64 tcp_payload_len = (__u64)(data_end - tcp_payload);

    /* Dump basic TCP packet information */
    bpf_printk("=== TCP Packet Info ===");
    /* CORRECT: Use %pI4 for IP addresses */
    bpf_printk("SRC IP: %pI4:%d -> DST IP: %pI4:%d", 
               &ip->saddr, bpf_ntohs(tcp->source),
               &ip->daddr, bpf_ntohs(tcp->dest));

    /* TCP Flags */
    bpf_printk("TCP Flags: [%s%s%s%s%s%s]",
               tcp->fin ? "FIN " : "",
               tcp->syn ? "SYN " : "",
               tcp->rst ? "RST " : "",
               tcp->psh ? "PSH " : "",
               tcp->ack ? "ACK " : "",
               tcp->urg ? "URG" : "");

    /* TCP Header information */
    bpf_printk("TCP Header: seq=%u ack=%u doff=%d (hdr_len=%d, payload_len=%d) window=%d",
               bpf_ntohl(tcp->seq),
               bpf_ntohl(tcp->ack_seq),
               tcp->doff,
               tcp_header_len,
               tcp_payload_len,
               bpf_ntohs(tcp->window));

    bpf_printk("================================\n");
    return TC_ACT_OK;
}