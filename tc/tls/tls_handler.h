#pragma once

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_TLS_RECORDS (36)

/* Common version values */
typedef enum tls_version {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
} tls_version_t;

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


enum tls_handshake_message_type {
    HELLO_REQUEST = 0,               //  0	hello_request	Запрос на повторное рукопожатие
    CLIENT_HELLO = 1,               //  1	client_hello	Клиент предлагает параметры соединения
    SERVER_HELLO = 2,               //  2	server_hello	Сервер выбирает параметры
    NEW_SESSION_TICKET = 4,               //  4	new_session_ticket	TLS 1.3: новый тикет сессии
    CERTIFICATE = 11,                // 11	certificate	Сертификат сервера (или клиента)
    KEY_EXCHANGE = 12,                // 12	server_key_exchange	Ключи для Diffie-Hellman (не в TLS 1.3)
    REQUEST_CERTIFICATE = 13,                // 13	certificate_request	Запрос сертификата клиента
    SERVER_HELLO_DONE = 14,                // 14	server_hello_done	Сервер закончил свою часть
    CERTIFICATE_VERIFY = 15,                // 15	certificate_verify	Подтверждение владения сертификатом
    CLIENT_KEY_EXCHANGE = 16,                // 16	client_key_exchange	Ключи клиента (для RSA/DHE)
    FINISHED = 20,                // 20	finished	Подтверждение завершения рукопожатия
} tls_handshake_message_type_t;

typedef struct tls_handshake {
    __u8  msg_type;      // offset 0: тип сообщения
    __u8  length[3];     // offset 1-3: длина body (24-bit, big-endian!)
    __u8  body[0];       // variable: TLS handshake body
} __attribute__((packed)) tls_handshake_t;

// Функция для преобразования 24-bit big-endian в uint32_t
static inline __u32 get_tls_handshake_length(struct tls_handshake* handshake) {
    return (handshake->length[0] << 16) | (handshake->length[1] << 8) | handshake->length[2];
}

// typedef struct tls_client_hello {
//     /* Part 1: Fixed fields */
//     __u16 client_version;           // offset 0-1: TLS version client supports
    
//     /* Part 2: Random (32 bytes) */
//     __u8  random[32];               // offset 2-33: 4 bytes timestamp + 28 random
    
//     /* Part 3: Session ID */
//     __u8  session_id_len;           // offset 34: length of session ID
//     __u8  session_id[0];            // variable: session ID (if any)
    
//     /* Part 4: Cipher Suites */
//     __u16 cipher_suites_len;        // length in bytes
//     __u16 cipher_suites[0];         // variable: list of cipher suites (each 2 bytes)
    
//     /* Part 5: Compression Methods */
//     __u8  compression_methods_len;  // length in bytes
//     __u8  compression_methods[0];   // variable: list of compression methods
    
//     /* Part 6: Extensions */
//     __u16 extensions_len;           // length in bytes
//     __u8  extensions[0];            // variable: TLS extensions
// } __attribute__((packed)) tls_client_hello_t;

// typedef struct tls_server_hello {
//     /* Part 1: Fixed fields */
//     __u16 server_version;           // offset 0-1: chosen TLS version
    
//     /* Part 2: Random (32 bytes) */
//     __u8  random[32];               // offset 2-33: server random
    
//     /* Part 3: Session ID */
//     __u8  session_id_len;           // offset 34: length of session ID
//     __u8  session_id[0];            // variable: session ID
    
//     /* Part 4: Chosen parameters */
//     __u16 cipher_suite;             // chosen cipher suite (2 bytes)
//     __u8  compression_method;       // chosen compression method
    
//     /* Part 5: Extensions (optional, TLS 1.3 requires them) */
//     __u16 extensions_len;           // may be present
//     __u8  extensions[0];            // variable: TLS extensions
// } __attribute__((packed)) tls_server_hello_t;

static __always_inline void handle_tsl_handshake(struct tls_handshake* handshake, __u8* data_end) {
    const __u32 handshake_len = get_tls_handshake_length(handshake);
    bpf_printk("TLS handshake: type=%d, len=%d", handshake->msg_type, handshake_len);

    switch (handshake->msg_type) {
        case CLIENT_HELLO: {
            bpf_printk("ClientHello");
            break;
        }
        case SERVER_HELLO: {
            bpf_printk("ServerHello");
            break;
        }
        default: break;
    }
}

static __always_inline int handle_tls(__u8* tcp_payload, __u32 tcp_payload_len, __u8* data_end) {
    #pragma unroll
    for (int i = 0; i < MAX_TLS_RECORDS; ++i) {
         /* Parse TLS Record */
        if (tcp_payload >= data_end || tcp_payload_len < sizeof(struct tls_record)) {
            return TC_ACT_OK;
        }

        struct tls_record *tls_record = (struct tls_record*)tcp_payload;
        // if ((__u8*)(tls_record + 1) > data_end) {
        //     return TC_ACT_OK;
        // }

        /* Validate length (max 2^14 = 16384 per RFC 5246) */
        __u16 tls_record_length = bpf_ntohs(tls_record->length);
        __u8 *tls_record_end = tcp_payload + sizeof(struct tls_record) + tls_record_length;
        if (tls_record_end > data_end || tls_record_length > 16384) {
            return TC_ACT_OK;
        }

         /* Validate TLS version */
        __u16 tls_record_version = bpf_ntohs(tls_record->version);
        switch (tls_record_version) {
            case SSL_3_0:
            case TLS_1_0:
            case TLS_1_1:
            case TLS_1_2:
                break;
            default:
                bpf_printk("Invalid tls version: %d", tls_record_version);
                return TC_ACT_OK;
        }

         /* Handle TLS content type */
        __u8 tls_record_content_type = tls_record->content_type;
        switch (tls_record_content_type) {
            case application_data: {
                bpf_printk("TLS RECORD: content type=Application Data");
                break;
            }
            case handshake: {
                struct tls_handshake* handshake = (struct tls_handshake*)(tls_record + 1);
                if ((__u8*)(handshake + 1) > tls_record_end) {
                    return TC_ACT_OK;
                }

                __u32 handshake_len = get_tls_handshake_length(handshake);
                if ((__u8*)handshake + sizeof(struct tls_handshake) + handshake_len > tls_record_end) {
                    return TC_ACT_OK;
                }

                handle_tsl_handshake(handshake, tls_record_end);
                break;
            }
            case change_cipher_spec: break; // skip: TODO
            case alert: break; // skip: TODO
            default:
                bpf_printk("Invalid tls content type: %d", tls_record_content_type);
                return TC_ACT_OK;
        }

         /* Log TLS record info */
        bpf_printk("TLST RECORD: content_type=%d, version=%d, length=%d", tls_record_content_type, tls_record_version, tls_record_length);
        tcp_payload = tls_record_end;
        tcp_payload_len -= data_end - tcp_payload;
        //tcp_payload_len -= sizeof(struct tls_record) + tls_record_length;
    }
    return TC_ACT_OK;
}

static __always_inline int parse_tcp(struct __sk_buff *skb) {
    // =========================================================
    // ШАГ 1: Линеаризуем пакет (подтягиваем все фрагменты)
    // =========================================================
    // Запрашиваем весь пакет целиком
    // https://stackoverflow.com/questions/78041475/how-to-read-arbitrary-len-bytes-using-helper-bpf-skb-load-bytes
    if (bpf_skb_pull_data(skb, skb->len) < 0) {
        bpf_printk("Failed to pull data\n");
        return TC_ACT_OK;
    }

    __u8 *data_end = (__u8*)(long)skb->data_end;
    __u8 *data = (__u8*)(long)skb->data;

    /* Parse Ethernet */
    struct ethhdr *eth = (struct ethhdr*)data;
    if ((__u8*)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Check for IPv4 (ETH_P_IP) */
    if   (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    /* Parse IP */
    struct iphdr *ip = (struct iphdr*)(eth + 1);
    if ((__u8*)(ip + 1) > data_end) {
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
    __u32 tcp_header_len = tcp->doff * 4;  // doff is in 32-bit words

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
    if (tcp_payload + tcp_payload_len > data_end) {
        return TC_ACT_OK;
    }

    /* Dump basic TCP packet information */
    bpf_printk("=== TCP Packet Info ===");

    bpf_printk("SRC IP: %pI4:%d -> DST IP: %pI4:%d",
               &ip->saddr, bpf_ntohs(tcp->source),
               &ip->daddr, bpf_ntohs(tcp->dest));

    bpf_printk("TCP Flags: [%s%s%s%s%s%s]",
               tcp->fin ? "FIN " : "",
               tcp->syn ? "SYN " : "",
               tcp->rst ? "RST " : "",
               tcp->psh ? "PSH " : "",
               tcp->ack ? "ACK " : "",
               tcp->urg ? "URG" : "");

    bpf_printk("TCP Header: seq=%u ack=%u doff=%d payload_len=%d window=%d",
               bpf_ntohl(tcp->seq),
               bpf_ntohl(tcp->ack_seq),
               tcp->doff,
               tcp_payload_len,
               bpf_ntohs(tcp->window));

    if (tcp_payload_len == 0) {
        return TC_ACT_OK;
    }

    return handle_tls(tcp_payload, tcp_payload_len, data_end);
}
