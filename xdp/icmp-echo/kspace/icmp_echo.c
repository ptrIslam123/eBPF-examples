#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>

static __always_inline __u16 csum_fold(__u32 csum)
{
    // Суммируем старшие 16 бит с младшими 16 битами
    csum = (csum & 0xffff) + (csum >> 16);
    // Снова добавляем перенос
    csum = (csum & 0xffff) + (csum >> 16);
    // Берем дополнение до единицы и возвращаем окончательную контрольную сумму
    return (__u16)~csum;
}

static __always_inline void swap_eth_addr(__u8 *a, __u8 *b)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, a, ETH_ALEN);
    __builtin_memcpy(a, b, ETH_ALEN);
    __builtin_memcpy(b, tmp, ETH_ALEN);
}

static __always_inline void swap_ip_addr(__u32 *a, __u32 *b)
{
    __u32 tmp = *a;
    *a = *b;
    *b = tmp;
}

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx) {
    bpf_printk("---------------------------------------------------- received a packet---------------------------------\n");

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct icmphdr *icmp;
    
    // Проверка Ethernet заголовка
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("etherner check failed\n");
        return XDP_PASS;   
    }
    
    // Проверка IP заголовка
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("ip check failed\n");
        return XDP_PASS;
    }
    
    // Проверяем, что это ICMP
    if (ip->protocol != IPPROTO_ICMP) {
        bpf_printk("not icmp protocol, protocol=%d\n", ip->protocol);
        return XDP_PASS;
    }

    // Проверка ICMP заголовка
    icmp = (struct icmphdr *)(ip + 1);
    if ((void *)(icmp + 1) > data_end) {
        bpf_printk("icmp check failed\n");
        return XDP_PASS;
    }
    
    bpf_printk("...received icmp packet with type=%d\n", icmp->type);

    // Пропускаем пакеты, которые не являются ICMP Echo Request
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    // Меняем местами MAC-адреса источника и назначения
    swap_eth_addr(eth->h_dest, eth->h_source);
    // Меняем местами IP-адреса источника и назначения
    swap_ip_addr(&ip->saddr, &ip->daddr); 

    // Копируем icmp
    struct icmphdr icmp_before = *icmp;

    // Меняем флаг на ICMP Echo Reply
    icmp->type = ICMP_ECHOREPLY;

    // Инициализируем контрольную сумму нулем
    icmp->checksum = 0;
    __s64 value = bpf_csum_diff((void *)&icmp_before, sizeof(icmp_before), (void *)icmp, sizeof(*icmp), 0);
    if (value >= 0)
        icmp->checksum = csum_fold(value);
    else
        bpf_printk("bpf_csum_diff failed\n");

    // Дропаем ICMP пакеты
    bpf_printk("Retransmited ICMP packet\n");
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";