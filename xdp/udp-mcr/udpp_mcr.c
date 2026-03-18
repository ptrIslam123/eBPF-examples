#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifdef BPF

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define memcpy(DEST, SRC, N) __builtin_memcpy(DEST, SRC, N)

#else

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include "checksum.h"

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;

#define bpf_get_prandom_u32() 1
#define bpf_printk(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define bpf_ntohs(X) ntohs(X)
#define bpf_htons(X) htons(X)
#define bpf_ntohl(X) ntohl(X)
#define bpf_htonl(X) htonl(X)

#define XDP_PASS (0)
#define XDP_TX (1)
#define XDP_DROP (2)

#define always_inline 

__u32 gen_cookie() {
    return (__u32)rand();
}

#endif

// Сигнатуры MCR (запрос клиента на испытание)
#define MCRH3110_BYTE0 0x4D  // M
#define MCRH3110_BYTE1 0x43  // C
#define MCRH3110_BYTE2 0x52  // R
#define MCRH3110_BYTE3 0x48  // H
#define MCRH3110_BYTE4 0x33  // 3
#define MCRH3110_BYTE5 0x31  // 1
#define MCRH3110_BYTE6 0x31  // 1
#define MCRH3110_BYTE7 0x30  // 0

// MITIGATOR отвечает испытанием (сообщение Challenge, 8 байтов)
#define MCRC_BYTE0 0x4D  // M
#define MCRC_BYTE1 0x43  // C
#define MCRC_BYTE2 0x52  // R
#define MCRC_BYTE3 0x43  // C

// Клиент проходит испытание (сообщение Response, 400 байтов):
#define MCRR_BYTE0 0x4D  // M
#define MCRR_BYTE1 0x43  // C
#define MCRR_BYTE2 0x52  // R
#define MCRR_BYTE3 0x52  // R

static const __u32 crc32_table[]  = {
    0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
    0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
    0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
    0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
    0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
    0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
    0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
    0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a, 0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
    0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
    0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
    0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
    0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
    0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
    0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
    0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
    0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
    0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c, 0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
    0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
    0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
    0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c, 0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
    0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
    0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
    0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d, 0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
    0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
    0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
    0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
    0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
    0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
    0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee, 0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
    0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
    0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
    0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e, 0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351,
};

static __always_inline __u32 crc32_c(const __u8 *data, __u32 len, __u32 init) {
    __u32 crc = init;
    for (__u32 i = 0; i < len; ++i) {
        crc = crc32_table[(crc & 0xff) ^ data[i]] ^ (crc >> 8);
    }    
    return crc;
}

static __always_inline int handle_MCRC_request(
    struct ethhdr *eth, 
    struct iphdr *ip, 
    struct udphdr *udp,
    __u8* payload, __u8* payload_end
) { 
    payload[0] = MCRC_BYTE0;
    payload[1] = MCRC_BYTE1;
    payload[2] = MCRC_BYTE2;
    payload[3] = MCRC_BYTE3;

    __u32 cookie = bpf_htonl(gen_cookie());
    __builtin_memcpy(&payload[4], &cookie, 4);
    
    udp->len = bpf_htons(sizeof(struct udphdr) + 8);
    
    swap_mac(eth);
    swap_ip(ip);
    swap_udp_ports(udp);

    compute_ip_checksum(ip); 
    compute_udp_checksum(ip, udp);
    
    bpf_printk("MCR: Challenge sent, cookie=0x%x, ip_len=%d, udp_len=%d\n", 
               cookie, bpf_ntohs(ip->tot_len), bpf_ntohs(udp->len));
    return XDP_TX;
}

static __always_inline int handle_MCRR_reply(
    struct ethhdr *eth, 
    struct iphdr *ip, 
    struct udphdr *udp,
    __u8* payload, __u8* payload_end,
    __u8* secret_key, __u32 secret_key_len
) {
    __u8* cookie_bytes = &payload[4];

    __u32 hash1;
    __builtin_memcpy(&hash1, &payload[8], 4);

    __u32 hash2;
    __builtin_memcpy(&hash2, &payload[12], 4);

    __u8 hash1_data[4 + secret_key_len];
    __builtin_memcpy(hash1_data, cookie_bytes, 4);
    __builtin_memcpy(hash1_data + 4, secret_key, secret_key_len);

    __u32 expected_hash1 = crc32_c(hash1_data, sizeof(hash1_data), 0);
    
    __u32 expected_hash2 = crc32_c(cookie_bytes, 4, expected_hash1);

    if (hash1 != expected_hash1 || hash2 != expected_hash2) {
        bpf_printk("MCR: Invalid response\n");
        return XDP_DROP;
    }

    swap_mac(eth);
    swap_ip(ip);
    swap_udp_ports(udp);
    
    compute_ip_checksum(ip); 
    compute_udp_checksum(ip, udp);
    
    bpf_printk("MCR: Challenge pass!\n");
    return XDP_DROP;
}

int check_MCRH3110_signature(__u8 *payload, __u8* payload_end) {
    if (payload_end - payload != 400 || payload + 8 > payload_end) {
        return 0;
    }
    return (
        payload[0] == MCRH3110_BYTE0 &&
        payload[1] == MCRH3110_BYTE1 &&
        payload[2] == MCRH3110_BYTE2 &&
        payload[3] == MCRH3110_BYTE3 &&
        payload[4] == MCRH3110_BYTE4 &&
        payload[5] == MCRH3110_BYTE5 &&
        payload[6] == MCRH3110_BYTE6 &&
        payload[7] == MCRH3110_BYTE7
    );
}

int check_MCRR_signature(__u8 *payload, __u8* payload_end) {
    if (payload + 4 > payload_end) {
        return 0;
    }
    return (
        payload[0] == MCRR_BYTE0 &&
        payload[1] == MCRR_BYTE1 &&
        payload[2] == MCRR_BYTE2 &&
        payload[3] == MCRR_BYTE3
    );
}


int udp_mcr_entry(
    struct ethhdr *eth, 
    struct iphdr *ip, 
    struct udphdr *udp, 
    __u8* payload, __u8* payload_end,
    __u8* secret_key, __u32 secret_key_len
) {
    if (check_MCRH3110_signature(payload, payload_end)) {
        return handle_MCRC_request(eth, ip, udp, payload, payload_end);
    } else if (check_MCRR_signature(payload, payload_end)) {
        return handle_MCRR_reply(eth, ip, udp, payload, payload_end, secret_key, secret_key_len);
    } else {
        bpf_printk("MCR: Not udp mcr challenge packet\n");
    }
    return XDP_PASS; 
}