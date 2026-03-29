#include <linux/bpf.h>      // Basic eBPF definitions and types
#include <linux/if_ether.h> // Ethernet protocol definitions
#include <bpf/bpf_helpers.h> // eBPF helper functions
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "checksum.h"


// License declaration - mandatory for eBPF programs
// Kernel verifier checks this to ensure GPL compatibility
char LICENSE[] SEC("license") = "GPL";

static __always_inline void swap_mac(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

static __always_inline void swap_ip(struct iphdr *ip)
{
    __u32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

static __always_inline void swap_tcp(struct tcphdr *tcp)
{
    __u16 tmp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp;
}

static __always_inline __u32 generate_isn() {
    return bpf_get_prandom_u32();
}

static __always_inline int handle_tcp_syn(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, __u8* data_end) {
    // Client chooses a random initial sequence number (tcp->seq)
    // This packet contains:
    //  * SYN flag = 1
    //  * Sequence number = tcp->seq
    //  * No payload (usually)
    //  * Client's window size, MSS, etc.

    // Purpose: Client announces it wants to establish a connection and provides its initial sequence number.

    //  * SYN = 1, ACK = 1 flags
    //  * Server's own Initial Sequence Number (tcp->seq).
    //          Who sets it: The sender of the packet.
    //          What it represents: The byte number of the first data byte in this packet
    //          Purpose: Tracks the sender's data bytes.
    //          Direction: Each direction has its own sequence number space
    //
    //  * Acknowledgment Number (ack_seq): Expected: client_seq + 1
    //          Purpose: Confirms receipt of the other side's data
    //          Who sets it: The receiver of data (acknowledging what they received)
    //          What it represents: The byte number that the sender expects to receive next
    //          Direction: Independent from sequence numbers

   __u32 client_seq = bpf_ntohl(tcp->seq);

    // Set correct flags (SYN+ACK)
    tcp->syn = 1;
    tcp->ack = 1;
    tcp->rst = 0;
    tcp->fin = 0;
    tcp->psh = 0;
    tcp->urg = 0;

    // Set server's own sequence number (MUST be different)
    __u32 server_isn = generate_isn();  // Different from client_seq
    tcp->seq = bpf_htonl(server_isn);

    // Set acknowledgment number (MUST be client_seq + 1)
    tcp->ack_seq = bpf_htonl(client_seq + 1);

    // Set server's window size
    tcp->window = bpf_htons(65535);  // default window size

    // Set ip TTL
    ip->ttl = 64; // default ttl

    // Swap everything first
    swap_mac(eth);
    swap_ip(ip);
    swap_tcp(tcp);

    // Recalculate TCP checksum
    compute_ipv4_checksum(ip);
    compute_tcp_checksum(ip, (__u16*)tcp, data_end);
    // Transmit modified packet back out same interface
    return XDP_TX;
}

static __always_inline int handle_tcp_echo(
    struct ethhdr *eth,
    struct iphdr *ip,
    struct tcphdr *tcp,
    __u8* payload,
    __u32 payload_len,
    __u8* data_end
) {
    // Check we can read payload (if needed for echo)
    if (payload + payload_len > data_end)
        return XDP_DROP;

    // // Проверка: можем ли прочитать 10 байт (индексы 0-9)
    // if (payload + 10 > data_end) {
    //     return XDP_DROP; // или XDP_PASS, если хочешь пропустить короткие
    // }

    // // Вывод первых 10 байт
    // for (int i = 0; i < 10; i++) {
    //     bpf_printk("byte[%d] = 0x%02x (%c)", i, payload[i], payload[i]);
    // }

    // Save original values before swap
    __be32 orig_seq = tcp->seq;
    __be32 orig_ack = tcp->ack_seq;
    __u32 orig_payload_len = payload_len;

    // Swap L2/L3/L4 addresses
    swap_mac(eth);
    swap_ip(ip);
    swap_tcp(tcp);  // swaps ports only

    // Fix TCP sequence numbers for ACK response
    // New SEQ = old ACK
    // New ACK = old SEQ + payload_len (or 1 for SYN/FIN)
    tcp->seq = orig_ack;

    // For pure ACK without payload, add received payload_len
    // For SYN, add 1; for FIN, add 1; for data, add payload_len
    __u32 ack_increment = payload_len;
    if (tcp->syn) ack_increment = 1;
    if (tcp->fin) ack_increment = 1;
    if (orig_payload_len == 0 && !tcp->syn && !tcp->fin) ack_increment = 0;

    tcp->ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + ack_increment);

    // Set ACK flag (clear others as needed)
    tcp->ack = 1;
    // tcp->psh = 0;  // optional: clear PSH for pure ACK

    // Recalculate TCP checksum (MANDATORY!)
    compute_ipv4_checksum(ip);
    compute_tcp_checksum(ip, (__u16*)tcp, data_end);
    // Transmit modified packet back out same interface

    /*
    Мы ожидаем что peer инициировавший tcp соединение на наш ответ tcp->syn & tcp->ack вернет пакет tcp->ack,
    на него отвечать не нужно, просто отбросим
    */
    return XDP_TX;
}

static __always_inline int handle_tcp_fin(
    struct ethhdr *eth,
    struct iphdr *ip,
    struct tcphdr *tcp,
    __u8* payload,
    __u32 payload_len,
    __u8* data_end
) {
    // Сохраняем оригинальные значения sequence numbers
    __be32 orig_seq = tcp->seq;
    __be32 orig_ack = tcp->ack_seq;

    bpf_printk("=== handle_tcp_fin ===");
    bpf_printk("Original: seq=%u, ack=%u, payload_len=%d",
               bpf_ntohl(orig_seq), bpf_ntohl(orig_ack), payload_len);

    // Меняем местами MAC адреса (source <-> destination)
    swap_mac(eth);

    // Меняем местами IP адреса (source <-> destination)
    swap_ip(ip);

    // Меняем местами TCP порты (source <-> destination)
    swap_tcp(tcp);

    // Формируем FIN-ACK ответ
    // SEQ = полученный ACK (это будет наш следующий sequence number)
    tcp->seq = orig_ack;

    // ACK = полученный SEQ + 1 (подтверждаем получение FIN)
    // Если есть данные (payload_len > 0), добавляем их тоже
    __u32 ack_increment = 1;  // FIN занимает 1 байт в sequence space
    if (payload_len > 0) {
        ack_increment += payload_len;
    }
    tcp->ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + ack_increment);

    // Устанавливаем флаги
    tcp->ack = 1;   // ACK флаг всегда установлен
    tcp->fin = 1;   // Отправляем FIN
    tcp->syn = 0;   // Сбрасываем SYN
    tcp->psh = 0;   // Сбрасываем PSH (опционально)
    tcp->rst = 0;   // Сбрасываем RST

    // Обновляем длину TCP заголовка (если нужно)
    // tcp->doff остается тем же (обычно 8 или 10)

    // Пересчитываем контрольные суммы
    compute_ipv4_checksum(ip);
    compute_tcp_checksum(ip, (__u16*)tcp, data_end);

    bpf_printk("Sending FIN-ACK: seq=%u, ack=%u",
               bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
    bpf_printk("Connection closing gracefully");
    return XDP_TX;
}

// XDP (eXpress Data Path) program section
// This function is called for every packet received on the interface
SEC("xdp")
int xdp_redirect_all(struct xdp_md *ctx)
{
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u8 *data = (__u8 *)(long)ctx->data;
    
    //bpf_printk("packet len=%d", data_end - data);
    
    /* Parse Ethernet */
    struct ethhdr *eth = (struct ethhdr*)data;
    if ((__u8*)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Check for IPv4 (ETH_P_IP) */
    if   (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    /* Parse IP */
    struct iphdr *ip = (struct iphdr*)(eth + 1);
    if ((__u8*)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    /* Check IP header length */
    __u8 ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20 || (__u8*)ip + ip_header_len > data_end) {
        return XDP_PASS;  // Changed from XDP_PASS to TC_ACT_OK
    }

    /* Check protocol */
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    /* TCP header */
    struct tcphdr *tcp = (struct tcphdr*)((__u8*)ip + ip_header_len);
    if ((__u8*)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    /* Get TCP header length (in bytes) */
    __u32 tcp_header_len = tcp->doff * 4;  // doff is in 32-bit words

    /* Check if tcp_header_len is valid (20-60 bytes) */
    if ((__u8*)tcp + tcp_header_len > data_end || 
        tcp_header_len < sizeof(struct tcphdr) || 
        tcp_header_len > 60) {
        bpf_printk("Invalid TCP header length: %d", tcp_header_len);
        return XDP_PASS;
    }

    /* Calculate TCP payload start */
    __u8 *payload = (__u8*)tcp + tcp_header_len;
    if (payload > data_end) {
        bpf_printk("TCP options exceed packet");
        return XDP_PASS;
    }
    __u64 payload_len = (__u64)(data_end - payload);
    if (payload + payload_len > data_end) {
        return XDP_PASS;
    }

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
               payload_len,
               bpf_ntohs(tcp->window));

    bpf_printk("================================\n");


    if (tcp->syn) {
        // Start three-way handshake process
        return handle_tcp_syn(eth, ip, tcp, data_end);
    }
    if (tcp->fin) {
        return handle_tcp_fin(eth, ip, tcp, payload, payload_len, data_end);;
    }

    if (tcp->ack && payload_len == 0) {
        // bpf_printk("ACK packet (handshake completion) - connection established");
        // Сохранить состояние соединения (опционально)
        // Но НЕ отправлять ответ
        return XDP_DROP;
    }


    if (payload_len > 0) {
        //bpf_printk("Handle non zer tcp payload\n");
        return handle_tcp_echo(eth, ip, tcp, payload, payload_len, data_end);
    }

    return XDP_PASS;
}

// How this works with userspace:
// 1. Userspace creates an AF_XDP socket bound to a specific queue
// 2. Userspace inserts socket FD into xsks_map at key = queue index
// 3. When packet arrives on that queue, XDP program redirects it to the socket
// 4. Userspace receives packet via AF_XDP socket, bypassing kernel network stack
//
// Performance benefits:
// - Zero-copy: packets go directly from NIC to userspace
// - Bypasses kernel networking stack
// - Very low latency (microseconds)
//
// Typical use cases:
// - High-performance packet processing
// - DDoS protection
// - Load balancers
// - Network monitoring
//
// Important notes:
// - Program runs in kernel context - must be safe and verifiable
// - Limited to 1 million instructions per packet
// - No loops (except bounded), no blocking operations
// - Must pass kernel verifier checks
