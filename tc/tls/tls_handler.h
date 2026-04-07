#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_TLS_DATA (2048)
#define MAX_TLS_RECORDS (10)
#define TLS_RECORD_HEADER_LEN (5)

struct tls_metadata {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 seq_num;
    __u8  tls_record_type;
    __u8  tls_version;
    __u16 tls_record_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_events SEC(".maps");

#define SUBMIT_TLS_DATA(metadata, tls_data, tls_data_end, data_end) \
    do { \
        \
        __u64 payload_len = (tls_data_end) - (tls_data); \
        if (tls_data + payload_len > data_end) { \
            bpf_printk("!!!!!!!!!!!!!!!!!!2"); \
            break; \
        } \
        \
        if (payload_len > MAX_TLS_DATA) { \
            payload_len = MAX_TLS_DATA; \
        } \
        \
        /* Резервируем место */ \
        void *ringbuf_ptr = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_metadata) + MAX_TLS_DATA, 0); \
        if (!ringbuf_ptr) { \
            bpf_printk("!!!!!!!!!!!!!!!!!!3"); \
            break; \
        } \
        \
        /* Копируем метаданные */ \
        if (bpf_probe_read_kernel(ringbuf_ptr, sizeof(struct tls_metadata), metadata) != 0) { \
            bpf_ringbuf_discard(ringbuf_ptr, 0); \
            bpf_printk("!!!!!!!!!!!!!!!!!!4"); \
            break; \
        } \
        \
        /* Копируем TLS данные */ \
        if (bpf_probe_read_kernel((__u8*)ringbuf_ptr + sizeof(struct tls_metadata), payload_len, tls_data) != 0) { \
            bpf_ringbuf_discard(ringbuf_ptr, 0); \
            bpf_printk("!!!!!!!!!!!!!!!!!!5"); \
            break; \
        } \
        \
        bpf_ringbuf_submit(ringbuf_ptr, 0); \
        bpf_printk("submit tls data: %d", sizeof(tls_data) + payload_len); \
    } while(0)


/* Common version values */
typedef enum tls_version {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
} tls_version_t;

/* Content Type Enumeration */
typedef enum tls_content_type {
    CHANGE_CIPHER_SPEC = 20,
    ALERT              = 21,
    HANDSHAKE          = 22,
    APPLICATION_DATA   = 23
} tls_content_type_t;

/* TLS Record Layer */
typedef struct tls_record {
    __u8  content_type;
    __u8 version_major;
    __u8 version_minor;
    __u16 length;
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

static __always_inline __u32 handle_tsl_handshake(
    struct tls_metadata* metadata,
    struct tls_handshake* handshake,
    __u8* tls_record_end, __u8* data_end
) {
    __u8* payload = (__u8*)(handshake + 1);
    if (payload > tls_record_end || payload > data_end) {
        return TC_ACT_OK;
    }

    metadata->tls_record_len = tls_record_end - payload;
    switch (handshake->msg_type) {
        case CLIENT_HELLO: {
            bpf_printk("ClientHello");
            metadata->tls_record_type = CLIENT_HELLO;
            SUBMIT_TLS_DATA(metadata, payload, tls_record_end, data_end);
            break;
        }
        case SERVER_HELLO: {
            bpf_printk("ServerHello");
            metadata->tls_record_type = SERVER_HELLO;
            SUBMIT_TLS_DATA(metadata, payload, tls_record_end, data_end);
            break;
        }
        case HELLO_REQUEST: { break; }
        case NEW_SESSION_TICKET: { break; }
        case CERTIFICATE: { break; }
        case KEY_EXCHANGE: { break; }
        case REQUEST_CERTIFICATE: { break; }
        case SERVER_HELLO_DONE: { break; }
        case CERTIFICATE_VERIFY: { break; }
        case CLIENT_KEY_EXCHANGE: { break; }
        case FINISHED: { break; }
    }
    return TC_ACT_OK;
}


static __always_inline __u32 handle_single_tls_record(
    struct tls_metadata* metadata,
    __u8 * payload_start, __u32 remaining_len, __u8* data_end
) {
    // 1. Проверка: влезает ли минимальный заголовок (5 байт) в оставшиеся данные?
    if (remaining_len < sizeof(struct tls_record)) {
        return 0; // Недостаточно данных даже на заголовок
    }

    // Дополнительная проверка по data_end для верификатора (на всякий случай)
    if (payload_start + sizeof(struct tls_record) > data_end) {
        return 0;
    }

    struct tls_record* tls_record = (struct tls_record*)payload_start;

    // 2. Читаем длину контента
    __u32 tls_record_len = bpf_ntohs(tls_record->length);

    /* Validate length (max 2^14 = 16384 per RFC 5246) */
    if (tls_record_len > 16384) {
        return 0;
    }

    __u32 total_tls_record_size = sizeof(struct tls_record) + tls_record_len;

    // 3. Проверка: влезает ли ВЕСЬ рекорд (заголовок + контент) в пакет?
    if (total_tls_record_size > remaining_len) {
        return 0; // Рекорд обрезан, ждем следующий пакет
    }

    __u8* tls_record_end = payload_start + total_tls_record_size;
    if (tls_record_end > data_end) {
        return 0;
    }

    bpf_printk("TLS Type: %d, Content Len: %d", tls_record->content_type, tls_record_len);

     /* Handle TLS content type */
    __u8 tls_record_content_type = tls_record->content_type;
    switch (tls_record_content_type) {
        case APPLICATION_DATA: {
            bpf_printk("TLS RECORD: content type=Application Data");
            break;
        }
        case HANDSHAKE: {
            bpf_printk("TLS RECORD: handshake");
            struct tls_handshake* handshake = (struct tls_handshake*)(tls_record + 1);
            if ((__u8*)(handshake + 1) > tls_record_end || (__u8*)(handshake + 1) > data_end) {
                return TC_ACT_OK;
            }

            __u32 handshake_len = get_tls_handshake_length(handshake);
            if ((__u8*)(handshake + 1) + handshake_len > tls_record_end) {
                return TC_ACT_OK;
            }

            metadata->tls_record_type = HANDSHAKE;
            handle_tsl_handshake(metadata, handshake, tls_record_end, data_end);
            break;
        }
        case CHANGE_CIPHER_SPEC: break; // skip: TODO
        case ALERT: break; // skip: TODO
        default:
            bpf_printk("Invalid tls content type: %d", tls_record_content_type);
            return TC_ACT_OK;
    }
    return total_tls_record_size;
}

static __always_inline int handle_tls(
    struct tls_metadata* metadata,
    __u8* tcp_payload, __u32 tcp_payload_len,
    __u8* data_end
) {
    __u32 processed_bytes = 0;
    __u32 current_offset = 0;

    // Попытка обработать до 5 записей (ручная развертка вызовов)
    // Можно заменить на цикл, если ядро новое, но вызовы функций инлайнятся хорошо

    // --- Запись 1 ---
    processed_bytes = handle_single_tls_record(
        metadata,
        tcp_payload + current_offset,
        tcp_payload_len - current_offset,
        data_end
    );
    if (processed_bytes == 0) return TC_ACT_OK; // Конец или ошибка
    current_offset += processed_bytes;

    // --- Запись 2 ---
    processed_bytes = handle_single_tls_record(
        metadata,
        tcp_payload + current_offset,
        tcp_payload_len - current_offset,
        data_end
    );
    if (processed_bytes == 0) return TC_ACT_OK;
    current_offset += processed_bytes;

    // --- Запись 3 ---
    processed_bytes = handle_single_tls_record(
        metadata,
        tcp_payload + current_offset,
        tcp_payload_len - current_offset,
        data_end
    );
    if (processed_bytes == 0) return TC_ACT_OK;
    current_offset += processed_bytes;

    // Можешь добавить 4-ю и 5-ю по аналогии, если ожидаешь много мелких записей

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

    struct tls_metadata metadata = {};

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

    return handle_tls(&metadata, tcp_payload, tcp_payload_len, data_end);
}
