#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/types.h>

#include <thread>
#include <chrono>

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

std::atomic<bool> running{true};

// Структура события (должна совпадать с eBPF-программой)
struct event {
    __u8 protocol;
    __u32 packet_size;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// Обработчик сигналов (Ctrl+C)
void signal_handler(int) {
    running = false;
}

// Callback для ring buffer
static int handle_event(void *ctx, void *data, size_t size) {
    const auto *e = static_cast<event*>(data);
    printf("Packet: proto=%u, size=%u, %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           e->protocol,
           e->packet_size,
           (e->saddr >> 24) & 0xFF, (e->saddr >> 16) & 0xFF,
           (e->saddr >> 8) & 0xFF, e->saddr & 0xFF,
           e->sport,
           (e->daddr >> 24) & 0xFF, (e->daddr >> 16) & 0xFF,
           (e->daddr >> 8) & 0xFF, e->daddr & 0xFF,
           e->dport);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <ifname> <xdp-obj-path>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *xdp_obj_path = argv[2];
    struct bpf_object *obj = nullptr;
    struct ring_buffer *rb = nullptr;
    int ifindex, prog_fd, map_fd;

    // 1. Настройка обработчика сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 2. Получаем индекс интерфейса
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    // 3. Загружаем объект BPF
    obj = bpf_object__open(xdp_obj_path);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // 4. Загружаем программу в ядро
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    // 5. Прикрепляем XDP-программу
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_parser"));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find XDP program\n");
        goto cleanup;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Failed to attach XDP program\n");
        goto cleanup;
    }

    // 6. Настраиваем ring buffer
    map_fd = bpf_object__find_map_fd_by_name(obj, "ringbuf");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ringbuf map\n");
        goto detach;
    }

    rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto detach;
    }

    printf("Monitoring XDP events on interface %s. Press Ctrl+C to stop.\n", ifname);

    // 7. Основной цикл чтения событий
    while (running) {
        int err = ring_buffer__poll(rb, 100 /* timeout (ms) */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // 8. Очистка
detach:
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}