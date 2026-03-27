#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Common version values */
#define SSL_3_0     0x0300
#define TLS_1_0     0x0301
#define TLS_1_1     0x0302
#define TLS_1_2     0x0303

/* Content Type Enumeration */
typedef enum tls_content_type {
    change_cipher_spec = 20,
    alert              = 21,
    handshake          = 22,
    application_data   = 23
} tls_content_type_t;

/* TLS Record Layer */
typedef struct tls_record {
    __u8  content_type;
    __u16 version;           /* Network byte order! */
    __u16 length;              /* Network byte order! */
} __attribute__((packed)) tls_record_t;

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    __u8 *data_end = (__u8*)(long)skb->data_end;
    __u8 *data = (__u8*)(long)skb->data;

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
    if ((__u8*)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Check IP header length and protocol */
    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }
    __u8 ip_header_len = ip->ihl * 4;

    /* Parse TCP */
    struct tcphdr *tcp = (struct tcphdr*)((__u8*)ip + ip_header_len);
    if ((__u8*)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Calculate TCP header length and payload offset */
    __u8 tcp_header_len = tcp->doff * 4;
    __u8 *tcp_payload = (__u8*)tcp + tcp_header_len;
    
    /* Check if we have any TCP payload */
    if (tcp_payload >= data_end) {
        return TC_ACT_OK;
    }

    /* Parse TLS Record */
    struct tls_record *tls_record = (struct tls_record*)tcp_payload;
    if ((__u8*)(tls_record + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Validate TLS content type */
    __u8 tls_content_type = tls_record->content_type;
    switch (tls_content_type) {
        case change_cipher_spec:
        case alert:
        case handshake:
        case application_data: 
            break;
        default:
            return TC_ACT_OK;
    }

    /* Validate TLS version */
    __u16 tls_version = bpf_ntohs(tls_record->version);
    switch (tls_version) {
        case SSL_3_0:
        case TLS_1_0:
        case TLS_1_1:
        case TLS_1_2:
            break;
        default:
            return TC_ACT_OK;
    }

    /* Validate length (max 2^14 = 16384 per RFC 5246) */
    __u16 tls_payload_length = bpf_ntohs(tls_record->length);
    if (tls_payload_length > 16384) {
        return TC_ACT_OK;
    }

    /* Check if full TLS payload is present */
    __u8 *tls_payload_end = (__u8*)tls_record + sizeof(struct tls_record) + tls_payload_length;
    if (tls_payload_end > data_end) {
        return TC_ACT_OK;  /* Fragmented or incomplete */
    }

    /* Log TLS record info */
    bpf_printk("TLS %d version=0x%04x length=%u", tls_content_type, tls_version, tls_payload_length);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";