#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <ifname> <xdp-obj-path> <xdp-app-name>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj;
    int prog_fd, ifindex;
    const char *ifname = argv[1];
    const char *xdp_obj_path = argv[2];
    const char *xdp_app_name = argv[3];

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

    printf("XDP program attached to %s. Press Enter to detach...\n", ifname);
    getchar();

    // 6. Отсоединяем программу
    bpf_set_link_xdp_fd(ifindex, -1, flags);
    bpf_object__close(obj);
    return 0;
}