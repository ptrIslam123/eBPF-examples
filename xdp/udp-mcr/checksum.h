#pragma once

#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <netinet/in.h>

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
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
void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

/* set tcp checksum: given IP header and UDP datagram */
void compute_udp_checksum(struct iphdr *pIph, struct udphdr* udp) {
    unsigned short *ipPayload = (unsigned short*)udp;
    unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);
    //printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
    //add the pseudo header 
    //printf("add pseudo headern");
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;
 
    //add the IP payload
    //printf("add ip payloadn");
    //initialize checksum to 0
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * ipPayload++;
        udpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        //printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
    //printf("one's complementn");
      sum = ~sum;
    //set computation result
    udphdrp->check = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}

// Функция для обмена MAC-адресов
static __always_inline void swap_mac(struct ethhdr *eth)
{
    uint8_t tmp[ETH_ALEN];
    memcpy(tmp, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp, ETH_ALEN);
}

// Функция для обмена IP-адресов
static __always_inline void swap_ip(struct iphdr *ip)
{
    uint32_t tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

// Функция для обмена UDP-портов
static __always_inline void swap_udp_ports(struct udphdr *udp)
{
    uint16_t tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp;
}
