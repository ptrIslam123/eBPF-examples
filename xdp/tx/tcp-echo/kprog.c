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

static __always_inline __u32 generate_isn() {
    return bpf_get_prandom_u32();
}

enum tcp_state {
    TCP_CONNECTION_INITIATED,   // Получен SYN, отправлен SYN-ACK
    TPC_CONNECTION_ESTABLISHED // Получен финальный ACK от peer
};

// Ключ для идентификации соединения (4-tuple)
struct connection_key {
    __u32 src_ip;      // IP клиента
    __u32 dst_ip;      // IP сервера
    __u16 src_port;    // Порт клиента
    __u16 dst_port;    // Порт сервера (4321)
};

// Минимальное состояние соединения
struct connection_state {
    __u32 server_seq;
    __u32 server_ack_seq;
    __u32 client_seq;
    __u32 client_ack_seq;

    // Состояние TCP
    __u8 state;            // Текущее состояние (enum tcp_state)
};

// BPF map для хранения соединений
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct connection_key);
    __type(value, struct connection_state);
} tcp_connections SEC(".maps");

static __always_inline int send_syn_ack(
    struct ethhdr *eth,
    struct iphdr *ip,
    struct tcphdr *tcp,
    __u8* data_end,
    __u32 client_isn,
    __u32 server_isn
) {
    // Set correct flags (SYN+ACK)
    tcp->syn = 1;
    tcp->ack = 1;
    tcp->rst = 0;
    tcp->fin = 0;
    tcp->psh = 0;
    tcp->urg = 0;

    // Set server's own sequence number
    tcp->seq = bpf_htonl(server_isn);

    // Set acknowledgment number (MUST be client_isn + 1)
    tcp->ack_seq = bpf_htonl(client_isn + 1);

    // Set server's window size
    tcp->window = bpf_htons(65535);

    // Set ip TTL
    ip->ttl = 64;

    // Swap addresses
    swap_mac(eth);
    swap_ip(ip);
    swap_tcp(tcp);

    // Recalculate checksums
    compute_ipv4_checksum(ip);
    compute_tcp_checksum(ip, (__u16*)tcp, data_end);

    return XDP_TX;
}

static __always_inline int handle_tcp_echo(
    struct connection_key* conn_key,
    struct connection_state* conn_state,
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
   conn_state->state = 0;

   (void)bpf_map_update_elem(&tcp_connections, &conn_key, &conn_state, BPF_NOEXIST);
    return XDP_TX;
}

/*
        TCP Connection Establishment Workflow

CLIENT                                       SERVER
   |                                            |
   | 1. SYN (seq=x, ISN(random init seqnum))    |
   |------------------------------------------->|
   |                                            |
   | 2. SYN-ACK (seq=y, ack_seq=x+1)            |
   |<-------------------------------------------|
   |                                            |
   | 3. ACK (seq=x+1, ack_seq=y+1)              |
   |------------------------------------------->|
   |                                            |
   |         CONNECTION ESTABLISHED             |
   |                                            |

    ### Step 1: SYN
    - The client sends: Packet with the SYN flag
    - Contains: Sequence number = x (random number)

    ### Step 2: SYN-ACK
    - The server must send a packet with the SYN + ACK flags
    - Contains:
    - Sequence number = y (its own random number)
    - Acknowledgment number = x + 1

    ### Step 3: ACK
    - The client sends a final packet with the ACK flag
    - Sequence number = x + 1
    - Acknowledgment number = y + 1
    After this packet, the client and server consider the connection established.

    ## Key Points
    - ISN (Initial Sequence Number) - Random number, chosen independently by each side
    - Sequence number (seq) - Number of the first byte of data in this packet
    - Acknowledgment number (ack) - Number of the next byte expected from the other side
    - Payload -  Handshake packets typically lack
*/
static __always_inline int handle_tcp_syn(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, __u8* data_end) {
    struct connection_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    struct connection_state* existing = bpf_map_lookup_elem(&tcp_connections, &key);
    if (!existing) {
        // ========== New connection ==========

        __u32 client_seq = bpf_ntohl(tcp->seq);
        // Set server's own sequence number (MUST be different)
        __u32 server_isn = generate_isn();  // Different from client_seq

        struct connection_state new = {
            .seq = client_seq + 1,
            .ack_seq = server_isn,
            .state = TCP_CONNECTION_INITIATED,
        };
        (void)bpf_map_update_elem(&tcp_connections, &key, &new, BPF_NOEXIST);
        return send_syn_ack(eth, ip, tcp, data_end, client_seq, server_isn);
    } else {
        // ========== Existing conection ==========

        // Handling repeated SYN
        if (existing->state == TCP_CONNECTION_INITIATED) {
            // The client did not receive our SYN-ACK, we send it again
            bpf_printk("Duplicate SYN, resending SYN-ACK for state=%d", existing->state);

            __u32 client_seq = existing->client_seq - 1;  // ISN from client
            __u32 server_isn = existing->server_seq;

            (void)bpf_map_update_elem(&tcp_connections, &key, existing, BPF_ANY);
            return send_syn_ack(eth, ip, tcp, data_end, client_seq, server_isn);
        } else {
            // The connection is already in a different state - ignore SYN
            bpf_printk("Ignoring SYN, connection in state=%d", existing->state);
            return XDP_DROP;
        }
    }
}

static __always_inline int handle_tcp_ack(
    struct ethhdr *eth,
    struct iphdr *ip,
    struct tcphdr *tcp,
    __u8* payload,
    __u32 payload_len,
    __u8* data_end
) {
    struct connection_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    struct connection_state* existing = bpf_map_lookup_elem(&tcp_connections, &key);
    if (!existing) {
        return XDP_DROP;
    }

    switch (existing->state) {
        case TCP_CONNECTION_INITIATED: {
            // мы получили финальный tcp ACK от peer
            existing->state = TPC_CONNECTION_ESTABLISHED;
            bpf_map_update_elem(&tcp_connections, &key, existing, BPF_ANY);
            return XDP_DROP;
        }
        case TPC_CONNECTION_ESTABLISHED: {
            if (payload_len > 0) {
                return handle_tcp_echo(&key, existing, eth, ip, tcp, payload, payload_len, data_end);
            } else if (payload_len == 0) {
                __u32 client_seq = bpf_ntohl(tcp->seq);
                __u32 client_ack_seq = bpf_ntohl(tcp->ack_seq);
                if (existing->seq == client_ack_seq) {
                    return XDP_DROP;
                }



                if (existing->seq !tcp->syn && !tcp->fin && !tcp->rst) {
                    /*
                                Client sends ACK to confirm
                      SERVER                                  CLIENT
                        |                                         |
                        | 1. Data (seq=x, len=y)                  |
                        |---------------------------------------->|
                        |                                         |
                        | 2. Pure ACK (ack_seq=x+y, len=0)        |
                        |<----------------------------------------|
                        |                                         |
                    */
                    // Подтверждение получения наших данных
                    return XDP_DROP;
                }
                // TODO: пока не обрабаотываются эти случаи
                // Window update ACK (когда изменилось окно)
                // Keep-alive ACK
                // DUP ACK (при потере пакетов)
                return XDP_DROP;
            }
        }
        default:
            return XDP_DROP;
    }
}

static __always_inline int handle_tcp_rst(
    struct ethhdr *eth,
    struct iphdr *ip,
    struct tcphdr *tcp,
    __u8* payload,
    __u32 payload_len,
    __u8* data_end
) {
    struct connection_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    struct connection_state *state = bpf_map_lookup_elem(&tcp_connections, &key);
    if (state) {
        bpf_printk("Found connection state: client_seq=%u, server_seq=%u, state=%d",
                   state->client_seq, state->server_seq, state->state);
        /* Delete connection state immediately */
        (void)bpf_map_delete_elem(&tcp_connections, &key);
        bpf_printk("Connection state deleted");
    } else {
        bpf_printk("RST for unknown connection");
    }
    return XDP_DROP;
}

/*
    TCP Connection Termination Workflow (Active Close from Client)

CLIENT                                    SERVER
   |                                         |
   | 1. FIN (seq = x, ack = y)               |
   |---------------------------------------->|
   |                                         |
   | 2. ACK (seq = y, ack = x+1)             |
   |<----------------------------------------|
   |                                         |
   | 3. FIN (seq = y, ack = x+1)             |
   |<----------------------------------------|
   |                                         |
   | 4. ACK (seq = x+1, ack = y+1)           |
   |---------------------------------------->|
   |                                         |
   |         CONNECTION CLOSED               |
   |                                         |

    ### WARNING:
    The server CAN and SHOULD combine steps 2 and 3 into a single FIN-ACK packet. This is the standard and recommended behavior.

    ### Step 1: FIN (Active Close)
    - The client sends: Packet with the FIN flag
    - Contains:
      - Sequence number = x (last sequence number + 1)
      - Acknowledgment number = y (acknowledges server's data)
      - FIN flag indicates no more data from client
    - FIN occupies 1 byte in sequence space

    ### Step 2: ACK (Passive Close - Server acknowledges FIN)
    - The server must send a packet with the ACK flag
    - Contains:
      - Sequence number = y (server's next sequence number)
      - Acknowledgment number = x + 1 (acknowledges client's FIN)
    - This ACK confirms receipt of client's FIN
    - Server enters CLOSE-WAIT state

    ### Step 3: FIN (Server initiates its own close)
    - The server sends: Packet with the FIN flag
    - Contains:
      - Sequence number = y (server's current sequence number)
      - Acknowledgment number = x + 1 (still acknowledging client's FIN)
    - Server enters LAST-ACK state

    ### Step 4: ACK (Final acknowledgment)
    - The client sends: Packet with the ACK flag
    - Contains:
      - Sequence number = x + 1 (client's next sequence number)
      - Acknowledgment number = y + 1 (acknowledges server's FIN)
    - Client enters TIME-WAIT state
    - Server closes connection after receiving this ACK

    ## Key Points

    ### FIN Flag Semantics:
    - FIN indicates the sender has no more data to send
    - FIN occupies 1 byte in the sequence number space
    - Each direction must be closed independently
    - Both sides must send and acknowledge FIN for full closure

    ### Sequence Number Handling:
    - FIN consumes one sequence number: seq = last_seq + 1
    - ACK for FIN: ack = received_seq + 1
    - After sending FIN, sender cannot send more data
    - Receiver can still send data after receiving FIN (half-close)

    ### State Transitions:
    - FIN-WAIT-1: After sending FIN, waiting for ACK
    - FIN-WAIT-2: After receiving ACK for FIN, waiting for peer's FIN
    - CLOSE-WAIT: After receiving FIN, waiting for application to close
    - LAST-ACK: After sending FIN, waiting for final ACK
    - TIME-WAIT: After sending final ACK, waiting for possible retransmissions
    - CLOSED: Connection fully terminated

    ### Important Considerations:
    1. **Half-Close**: After receiving FIN, server can still send data
    2. **Retransmission**: Lost FIN packets are retransmitted
    3. **Simultaneous Close**: Both sides can send FIN at the same time
    4. **TIME-WAIT**: Prevents delayed packets from interfering with new connections
    5. **RST Alternative**: Instead of FIN, connection can be aborted with RST

    ### FIN vs RST:
    - **FIN**: Graceful close, completes pending data transmission
    - **RST**: Abrupt close, discards pending data, immediate termination
    - FIN requires 4-way handshake, RST is immediate

    ### Common Issues:
    1. **FIN Retransmission**: If ACK not received, FIN is retransmitted
    2. **Half-Open Connections**: When one side crashes without sending FIN
    3. **Orphaned Connections**: FIN sent but never acknowledged
    4. **TIME-WAIT Accumulation**: Many connections in TIME-WAIT state
*/
static __always_inline int handle_tcp_fin(
    struct ethhdr *eth,
    struct iphdr *ip,
    struct tcphdr *tcp,
    __u8* payload,
    __u32 payload_len,
    __u8* data_end
) {
    struct connection_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    struct connection_state *state = bpf_map_lookup_elem(&tcp_connections, &key);
    if (!state) {
        return XDP_DROP;
    }

    // Сохраняем оригинальные значения sequence numbers
    __be32 orig_seq = tcp->seq;
    __be32 orig_ack = tcp->ack_seq;

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

    (void)bpf_map_delete_elem(&tcp_connections, &key);
    return XDP_TX;
}

// XDP (eXpress Data Path) program section
// This function is called for every packet received on the interface
SEC("xdp")
int xdp_tcp_echo_server(struct xdp_md *ctx)
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

    bpf_printk("TCP Header: seq=%u ack=%u doff=%d (hdr_len=%d, payload_len=%d) window=%d",
               bpf_ntohl(tcp->seq),
               bpf_ntohl(tcp->ack_seq),
               tcp->doff,
               tcp_header_len,
               payload_len,
               bpf_ntohs(tcp->window));

    bpf_printk("================================\n");

    if (tcp->syn) {
        // Start three-way handshake(tcp connection) process
        return handle_tcp_syn(eth, ip, tcp, data_end);
    }
    if (tcp->fin) {
        return handle_tcp_fin(eth, ip, tcp, payload, payload_len, data_end);;
    }
    if (tcp->ack) {
        return handle_tcp_ack(eth, ip, tcp, payload, payload_len, data_end);
    }
    if (tcp->rst) {
        return handle_tcp_rst(eth, ip, tcp, payload, payload_len, data_end);
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
