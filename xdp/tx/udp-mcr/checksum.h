#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>

#define ALWAYS_INLINE static inline


__always_inline static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  unsigned long sum = 0;

//   while (count > 1) {
//     sum += * addr++;
//     count -= 2;
//   }

  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&bpf_htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
__always_inline void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}


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
ALWAYS_INLINE void compute_udp_checksum(struct iphdr *pIph, struct udphdr* udp, __u8* end) {
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
    __u16 remaining = udpLen;
    #pragma unroll
    for (int i = 0; i < MAX_UDP_LENGTH; i++) {
        if (udpLen < 2)
            break;

        // Check bounds
        if ((void *)(ipPayload + 1) > end)
            break;

        sum += *ipPayload;
        ipPayload++;
        udpLen -= 2;
    }

    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        if (ipPayload + 1 > end) {
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


// #define MAX_UDP_SIZE 512
// static inline __u16 caludpcsum(struct iphdr *iph, struct udphdr *udph, void *data_end)
// {
//     __u32 csum_buffer = 0;
//     __u16 udp_len = bpf_ntohs(udph->len);
//     __u16 *buf = (void *)udph; (void)buf;

//     // Compute pseudo-header checksum
//     csum_buffer += (__u16)iph->saddr;
//     csum_buffer += (__u16)(iph->saddr >> 16);
//     csum_buffer += (__u16)iph->daddr;
//     csum_buffer += (__u16)(iph->daddr >> 16);
//     csum_buffer += (__u16)iph->protocol << 8;
//     csum_buffer += udph->len;

//     // // Compute checksum on udp header + payload
//     // for (int i = 0; i < MAX_UDP_SIZE; i += 2)
//     // {
//     //     if ((void *)(buf + 1) > data_end)
//     //     {
//     //         break;
//     //     }

//     //     csum_buffer += *buf;
//     //     buf++;
//     // }
//     // or
//     // csum_buffer = bpf_csum_diff(NULL, 0, udph, udp_len, csum_buffer);

//     if ((void *)buf + 1 <= data_end)
//     {
//         // In case payload is not 2 bytes aligned
//         csum_buffer += *(__u8 *)buf;
//     }

//     __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
//     csum = ~csum;
//     return csum;
// }

__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result !
    *csum = csum_fold_helper(*csum);
}

static inline __u16 compute_ipv4_checksum(struct iphdr* ip) {
    ip->check = 0;
    return csum_fold_helper(bpf_csum_diff(0, 0, (void*)ip, sizeof(*ip), 0));
}

// Функция для обмена MAC-адресов
ALWAYS_INLINE void swap_mac(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

// Функция для обмена IP-адресов
ALWAYS_INLINE void swap_ip(struct iphdr *ip)
{
    __u32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

// Функция для обмена UDP-портов
ALWAYS_INLINE void swap_udp_ports(struct udphdr *udp)
{
    __u16 tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp;
}
