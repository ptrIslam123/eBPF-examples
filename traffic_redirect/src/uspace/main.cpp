#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <net/if.h>
#include <linux/if_link.h>

/* ---------- КОНФИГУРАЦИЯ ---------- */
static constexpr size_t FRAME_SZ = 4096;      // Размер одного буфера
static constexpr size_t RING_SZ  = 4096;      // Количество буферов в кольце
static constexpr int    QUEUE_ID = 0;         // RX очередь (для lo всегда 0)
static constexpr char   IFNAME[] = "lo";      // Интерфейс

/* ---------- ОСНОВНАЯ ФУНКЦИЯ ---------- */
int main() {
    // Объявляем ВСЕ переменные в начале функции
    void *umem_area = nullptr;
    struct xsk_umem *umem = nullptr;
    struct xsk_socket *xsk = nullptr;
    struct xsk_ring_prod fq;    // Fill Queue
    struct xsk_ring_cons cq;    // Completion Queue
    struct xsk_ring_cons rxq;   // RX Queue
    struct xsk_ring_prod txq;   // TX Queue
    
    int ret = 0, xsks_map_fd = 0;
    uint32_t idx = 0;
    int packet_count = 0;
    
    printf("=== AF_XDP Packet Receiver ===\n");
    printf("Interface: %s, Queue: %d\n\n", IFNAME, QUEUE_ID);
    
    /* 1. Выделяем память для UMEM (должна быть выровнена по странице) */
    umem_area = aligned_alloc(4096, FRAME_SZ * RING_SZ);
    if (!umem_area) {
        perror("aligned_alloc");
        return 1;
    }
    printf("[1] UMEM allocated: %lu bytes\n", 
           (unsigned long)(FRAME_SZ * RING_SZ));
    
    /* 2. Создаем UMEM */
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SZ,
        .comp_size = RING_SZ,
        .frame_size = FRAME_SZ,
        .frame_headroom = 0,
        .flags = 0
    };
    
    ret = xsk_umem__create(&umem, umem_area, FRAME_SZ * RING_SZ, 
                          &fq, &cq, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %d\n", ret);
        throw 1;
    }
    printf("[2] UMEM created successfully\n");
    
    /* 3. Создаем AF_XDP сокет с ПРАВИЛЬНЫМИ флагами */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = RING_SZ,
        .tx_size = RING_SZ,
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, // Важно!
        .xdp_flags = XDP_FLAGS_SKB_MODE,     // Для loopback
        .bind_flags = XDP_COPY,              // Критично для lo!
    };
    
    ret = xsk_socket__create_shared(&xsk, IFNAME, QUEUE_ID,
                                    umem, &rxq, &txq, &fq, &cq, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create_shared failed: %d\n", ret);
        fprintf(stderr, "Возможные причины:\n");
        fprintf(stderr, "1. Интерфейс %s не поддерживает XDP\n", IFNAME);
        fprintf(stderr, "2. Не установлен флаг XDP_COPY для loopback\n");
        fprintf(stderr, "3. eBPF программа не загружена на интерфейс\n");
        throw 1;
    }
    printf("[3] AF_XDP socket created, fd=%d\n", xsk_socket__fd(xsk));
    
    /* 4. Открываем карту xsks_map и регистрируем сокет (КЛЮЧЕВОЙ ШАГ!) */
    xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map_fd < 0) {
        perror("bpf_obj_get(/sys/fs/bpf/xsks_map)");
        fprintf(stderr, "Убедитесь, что eBPF программа загружена: make load\n");
        throw 1;
    }
    
    ret = xsk_socket__update_xskmap(xsk, xsks_map_fd);
    if (ret) {
        fprintf(stderr, "xsk_socket__update_xskmap failed: %d\n", ret);
        fprintf(stderr, "Это самая частая причина проблем!\n");
        throw 1;
    }
    printf("[4] Socket registered in xsks_map[%d]\n", QUEUE_ID);
    
    /* 5. Заполняем Fill Queue буферами */
    uint32_t n = xsk_ring_prod__reserve(&fq, RING_SZ, &idx);
    if (n != RING_SZ) {
        fprintf(stderr, "Could only reserve %u of %lu FQ descriptors\n", 
                n, (unsigned long)RING_SZ);
        throw 1;
    }
    
    for (uint32_t i = 0; i < n; i++) {
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SZ;
    }
    xsk_ring_prod__submit(&fq, n);
    printf("[5] Fill Queue filled with %u buffers\n", n);
    printf("\n[READY] Waiting for packets (send ping to %s)...\n", IFNAME);
    
    /* 6. ОСНОВНОЙ ЦИКЛ ПРИЕМА ПАКЕТОВ */
    while (1) {
        uint32_t rx_idx = 0, fq_idx = 0;
        
        /* 6.1 Проверяем, есть ли пакеты в RX Queue */
        uint32_t rx_packets = xsk_ring_cons__peek(&rxq, 64, &rx_idx);
        
        if (rx_packets > 0) {
            /* 6.2 Обрабатываем каждый полученный пакет */
            for (uint32_t i = 0; i < rx_packets; i++) {
                uint64_t addr = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
                uint32_t len = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->len;
                
                packet_count++;
                printf("[PACKET #%d] %u bytes | Addr: 0x%lx\n", 
                       packet_count, len, (unsigned long)addr);
                
                /* Дополнительно: выводим первые 16 байт в hex */
                if (len > 0) {
                    uint8_t *pkt = (uint8_t*)umem_area + addr;
                    printf("  Hex: ");
                    for (uint32_t j = 0; j < (len < 16 ? len : 16); j++) {
                        printf("%02x ", pkt[j]);
                    }
                    printf("%s\n", len > 16 ? "..." : "");
                }
            }
            
            /* 6.3 Освобождаем пакеты из RX Queue */
            xsk_ring_cons__release(&rxq, rx_packets);
            
            /* 6.4 Возвращаем буферы обратно в Fill Queue */
            uint32_t filled = xsk_ring_prod__reserve(&fq, rx_packets, &fq_idx);
            for (uint32_t i = 0; i < filled; i++) {
                *xsk_ring_prod__fill_addr(&fq, fq_idx + i) = 
                    xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
            }
            xsk_ring_prod__submit(&fq, filled);
            
        } else {
            /* 6.5 Нет пакетов - небольшая пауза */
            usleep(1000); // 1ms
        }
    }
    return 0; 
// cleanup:
//     /* 7. Корректная очистка */
//     printf("\n[EXIT] Cleaning up...\n");
//     if (xsk) xsk_socket__delete(xsk);
//     if (umem) xsk_umem__delete(umem);
//     if (umem_area) free(umem_area);
    
//     return ret < 0 ? 1 : 0;
}