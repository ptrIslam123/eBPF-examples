#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>

#define ALWAYS_INLINE static inline

// Вспомогательная функция для сворачивания 32/64-битной суммы в 16-битную контрольную сумму
static inline __sum16 csum_fold_helper(__wsum csum) {
    __u32 sum = (__u32)csum;
    // Складываем старшие 16 бит с младшими
    sum = (sum & 0xffff) + (sum >> 16);
    // На случай переполнения после первого сложения
    sum += (sum >> 16);
    // Инверсия битов (стандарт Internet Checksum)
    return (__sum16)~sum;
}

#define MAX_UDP_LENGTH 1480
/* set tcp checksum: given IP header and UDP datagram */
static inline void compute_udp_checksum(struct iphdr *pIph, struct udphdr* udp, __u8* end) {
    unsigned long sum = 0;
    unsigned short *ipPayload = (unsigned short*)udp;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = bpf_htons(udphdrp->len);

    //add the pseudo header
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += bpf_htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;

    //add the IP payload
    //initialize checksum to 0
    udphdrp->check = 0;
    // while (udpLen > 1) {
    //     sum += * ipPayload++;
    //     udpLen -= 2;
    // }
    #pragma unroll
    for (int i = 0; i < MAX_UDP_LENGTH; i++) {
        if (udpLen < 2)
            break;

        // Check bounds
        if ((__u8*)(ipPayload + 1) > end)
            break;

        sum += *ipPayload;
        ipPayload++;
        udpLen -= 2;
    }

    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        if ((__u8*)(ipPayload + 1) > end) {
            bpf_printk("ipPayload + 1 < end!!!!");
            return;
        }
        sum += ((*ipPayload)&bpf_htons(0xFF00));
    }

    //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    //set computation result
    udphdrp->check = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}

#define MAX_TCP_LENGTH 516

/* set tcp checksum: given IP header and tcp segment */
static inline void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload, __u8* end) {
    unsigned long sum = 0;
    unsigned short tcpLen = bpf_ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += bpf_htons(IPPROTO_TCP);
    //the length
    sum += bpf_htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    // while (tcpLen > 1) {
    //     sum += * ipPayload++;
    //     tcpLen -= 2;
    // }
    #pragma unroll
    for (int i = 0; i < MAX_TCP_LENGTH; i++) {
        if (tcpLen < 2)
            break;

        // // Check bounds
        if ((__u8*)(ipPayload + 1) > end)
            break;

        sum += *ipPayload;
        ipPayload++;
        tcpLen -= 2;
    }

    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        if ((__u8*)(ipPayload + 1) > end) {
            bpf_printk("ipPayload + 1 < end!!!!");
            return;
        }
        sum += ((*ipPayload)&bpf_htons(0xFF00));
    }

    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&bpf_htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

static inline void compute_ipv4_checksum(struct iphdr* ip) {
    ip->check = 0;
    ip->check = csum_fold_helper(bpf_csum_diff(0, 0, (__be32*)ip, sizeof(*ip), 0));
}
