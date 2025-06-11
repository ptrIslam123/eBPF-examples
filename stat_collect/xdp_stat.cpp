#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/types.h>

#include <thread>
#include <chrono>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <ifname> <xdp-obj-path>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj;
    int prog_fd, map_fd, ifindex;
    const char *ifname = argv[1];
    const char *xdp_obj_path = argv[2];
    const char *xdp_app_name = "xdp_parser";
    const char *xdp_map_name = "packet_stat";

    // 1. Получаем индекс интерфейса
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    // 2. Загружаем объект BPF
    obj = bpf_object__open(xdp_obj_path);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // 3. Загружаем программу в ядро
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    // 4. Получаем файловый дескриптор программы
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, xdp_app_name));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // 5. Прикрепляем XDP-программу к интерфейсу (в режиме DRV/NATIVE)
    unsigned int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, flags) < 0) {
        fprintf(stderr, "Failed to attach XDP program\n");
        bpf_object__close(obj);
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    struct bpf_map *map = bpf_object__find_map_by_name(obj, xdp_map_name);
    if (!map) {
        fprintf(stderr, "Failed to find map '%s'\n", xdp_map_name);
        bpf_set_link_xdp_fd(ifindex, -1, flags);
        bpf_object__close(obj);
        return 1;
    }
    map_fd = bpf_map__fd(map);


    // 7. Пример: чтение данных из карты
    __u32 key = 0, next_key;
    __u64 value;

    printf("Current map contents:\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("Key: %u, Value: %llu\n", next_key, (unsigned long long)value);
        }
        key = next_key;
    }

    // 8. Пример: обновление значения в карте
    __u32 test_key = 123;
    __u64 new_value = 456;
    if (bpf_map_update_elem(map_fd, &test_key, &new_value, BPF_ANY) == 0) {
        printf("Updated key %u with value %llu\n", test_key, (unsigned long long)new_value);
    } else {
        perror("Failed to update map element");
    }

    // 9. Ожидание перед отключением
    printf("Press Enter to detach and exit...\n");
    getchar();

    // 10. Отсоединяем программу
    bpf_set_link_xdp_fd(ifindex, -1, flags);
    bpf_object__close(obj);
    return 0;
}