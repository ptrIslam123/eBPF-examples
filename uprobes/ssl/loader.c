// loader.c - Userspace program to trace SSL_write
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include "ssl_trace.h"

static volatile int exiting = 0;
static FILE *output_file = NULL;

// Signal handler
static void sig_handler(int sig) {
    printf("\nStopping tracer...\n");
    exiting = 1;
}

// Print hex dump of data
void print_hex_dump(const char *data, int len, int max_len) {
    int print_len = len;
    if (print_len > max_len && max_len > 0) {
        print_len = max_len;
    }
    
    printf("  Hex dump (%d bytes):\n", print_len);
    for (int i = 0; i < print_len; i += 16) {
        printf("  %04x: ", i);
        for (int j = 0; j < 16 && i + j < print_len; j++) {
            printf("%02x ", (unsigned char)data[i + j]);
        }
        printf(" ");
        for (int j = 0; j < 16 && i + j < print_len; j++) {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
    if (len > max_len && max_len > 0) {
        printf("  ... (%d more bytes)\n", len - max_len);
    }
}

// Handle SSL_write events
static int handle_ssl_write(void *ctx, void *data, size_t data_sz) {
    struct ssl_write_event *e = (struct ssl_write_event *)data;
    double timestamp = e->timestamp / 1000000000.0;
    
    printf("\n========================================\n");
    printf("[PID %d] %s - SSL_write\n", e->pid, e->comm);
    printf("Timestamp: %.6f seconds\n", timestamp);
    printf("SSL*: 0x%lx\n", e->ssl_ptr);
    printf("Buffer: 0x%lx\n", e->buf_ptr);
    printf("Requested: %d bytes\n", e->num_bytes);
    printf("Returned: %d bytes\n", e->ret_value);
    
    if (e->data_len > 0 && e->ret_value > 0) {
        printf("\nData written (%d bytes):\n", e->data_len);
        
        // Try to print as string if printable
        int printable = 1;
        for (int i = 0; i < e->data_len && i < 500; i++) {
            if (!isprint(e->data[i]) && e->data[i] != '\n' && 
                e->data[i] != '\r' && e->data[i] != '\t') {
                printable = 0;
                break;
            }
        }
        
        if (printable && e->data_len < 1000) {
            printf("  String: %.*s\n", e->data_len, e->data);
        } else {
            print_hex_dump(e->data, e->data_len, 256);
        }
    }
    
    // Write to file if specified
    if (output_file && e->data_len > 0) {
        fprintf(output_file, "[PID %d] SSL_write %d bytes:\n", e->pid, e->ret_value);
        fwrite(e->data, 1, e->data_len, output_file);
        fprintf(output_file, "\n\n");
        fflush(output_file);
    }
    
    return 0;
}

// Handle SSL_read events
static int handle_ssl_read(void *ctx, void *data, size_t data_sz) {
    struct ssl_read_event *e = (struct ssl_read_event *)data;
    double timestamp = e->timestamp / 1000000000.0;
    
    printf("\n========================================\n");
    printf("[PID %d] %s - SSL_read\n", e->pid, e->comm);
    printf("Timestamp: %.6f seconds\n", timestamp);
    printf("SSL*: 0x%lx\n", e->ssl_ptr);
    printf("Buffer: 0x%lx\n", e->buf_ptr);
    printf("Requested: %d bytes\n", e->num_bytes);
    printf("Returned: %d bytes\n", e->ret_value);
    
    if (e->data_len > 0 && e->ret_value > 0) {
        printf("\nData read (%d bytes):\n", e->data_len);
        print_hex_dump(e->data, e->data_len, 256);
    }
    
    return 0;
}

// Handle lost events
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

// Find the path to libssl.so
char* find_libssl() {
    static char path[512];
    const char *lib_paths[] = {
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/usr/lib64/libssl.so",
        "/usr/lib/libssl.so",
        "/lib/x86_64-linux-gnu/libssl.so",
        "/lib64/libssl.so",
        NULL
    };
    
    for (int i = 0; lib_paths[i]; i++) {
        if (access(lib_paths[i], R_OK) == 0) {
            strcpy(path, lib_paths[i]);
            return path;
        }
    }
    
    // Try to find using ldconfig
    FILE *fp = popen("ldconfig -p 2>/dev/null | grep libssl.so | head -1 | awk '{print $NF}'", "r");
    if (fp) {
        if (fgets(path, sizeof(path), fp)) {
            path[strcspn(path, "\n")] = 0;
            pclose(fp);
            if (access(path, R_OK) == 0) {
                return path;
            }
        }
        pclose(fp);
    }
    
    return NULL;
}

// Attach uprobe using the correct API
static struct bpf_link* attach_uprobe(struct bpf_program *prog, 
                                       const char *binary_path, 
                                       const char *symbol,
                                       bool retprobe) {
    struct bpf_link *link;
    
    if (retprobe) {
        link = bpf_program__attach_uretprobe(prog, false, -1, binary_path, 0, symbol);
    } else {
        link = bpf_program__attach_uprobe(prog, false, -1, binary_path, 0, symbol);
    }
    
    return link;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link;
    char *libssl_path;
    int err;
    int filter_pid = 0;
    
    printf("eBPF SSL_write/SSL_read Tracer\n");
    printf("================================\n\n");
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            filter_pid = atoi(argv[i+1]);
            printf("Filtering PID: %d\n", filter_pid);
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            output_file = fopen(argv[i+1], "w");
            if (output_file) {
                printf("Outputting to file: %s\n", argv[i+1]);
            }
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [-p PID] [-o output_file]\n", argv[0]);
            printf("  -p PID    Filter by process ID\n");
            printf("  -o FILE   Write captured data to file\n");
            return 0;
        }
    }
    
    // Find libssl
    libssl_path = find_libssl();
    if (!libssl_path) {
        fprintf(stderr, "Failed to find libssl.so\n");
        fprintf(stderr, "Make sure OpenSSL is installed\n");
        return 1;
    }
    printf("Found libssl at: %s\n\n", libssl_path);
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Bump RLIMIT_MEMLOCK
    struct rlimit rlim = {
        .rlim_cur = 128 * 1024 * 1024,
        .rlim_max = 128 * 1024 * 1024,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }
    
    // Open eBPF object file
    obj = bpf_object__open_file("ssl_trace.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %ld\n", 
                libbpf_get_error(obj));
        return 1;
    }
    
    // Load eBPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    // Set up filter if specified
    if (filter_pid > 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "filter_pids");
        if (map) {
            int map_fd = bpf_map__fd(map);
            uint32_t key = filter_pid;
            uint32_t val = 1;
            bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
            printf("Filter enabled for PID %d\n", filter_pid);
        }
    }
    
    // Attach probes
    int attached = 0;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        
        if (strcmp(prog_name, "trace_ssl_write_entry") == 0) {
            link = attach_uprobe(prog, libssl_path, "SSL_write", false);
            if (!libbpf_get_error(link)) {
                printf("✓ Attached to SSL_write (entry)\n");
                attached++;
            } else {
                fprintf(stderr, "✗ Failed to attach to SSL_write entry\n");
            }
        }
        else if (strcmp(prog_name, "trace_ssl_write_return") == 0) {
            link = attach_uprobe(prog, libssl_path, "SSL_write", true);
            if (!libbpf_get_error(link)) {
                printf("✓ Attached to SSL_write (return)\n");
                attached++;
            } else {
                fprintf(stderr, "✗ Failed to attach to SSL_write return\n");
            }
        }
        else if (strcmp(prog_name, "trace_ssl_read_entry") == 0) {
            link = attach_uprobe(prog, libssl_path, "SSL_read", false);
            if (!libbpf_get_error(link)) {
                printf("✓ Attached to SSL_read (entry)\n");
                attached++;
            } else {
                fprintf(stderr, "✗ Failed to attach to SSL_read entry\n");
            }
        }
        else if (strcmp(prog_name, "trace_ssl_read_return") == 0) {
            link = attach_uprobe(prog, libssl_path, "SSL_read", true);
            if (!libbpf_get_error(link)) {
                printf("✓ Attached to SSL_read (return)\n");
                attached++;
            } else {
                fprintf(stderr, "✗ Failed to attach to SSL_read return\n");
            }
        }
    }
    
    if (attached == 0) {
        fprintf(stderr, "No probes attached\n");
        goto cleanup;
    }
    
    printf("\nTracing SSL_write/SSL_read... Press Ctrl-C to stop.\n");
    printf("Run any HTTPS application to see events!\n\n");
    
    // Set up ring buffer for both maps
    struct bpf_map *map_write = bpf_object__find_map_by_name(obj, "ssl_write_events");
    struct bpf_map *map_read = bpf_object__find_map_by_name(obj, "ssl_read_events");
    
    if (map_write && map_read) {
        // Create ring buffer that polls both maps
        int map_write_fd = bpf_map__fd(map_write);
        int map_read_fd = bpf_map__fd(map_read);
        
        rb = ring_buffer__new(map_write_fd, handle_ssl_write, handle_lost_events, NULL);
        if (rb) {
            err = ring_buffer__add(rb, map_read_fd, handle_ssl_read, handle_lost_events);
            if (err < 0) {
                fprintf(stderr, "Failed to add read map to ring buffer\n");
            }
        }
    } else if (map_write) {
        int fd = bpf_map__fd(map_write);
        rb = ring_buffer__new(fd, handle_ssl_write, handle_lost_events, NULL);
    } else if (map_read) {
        int fd = bpf_map__fd(map_read);
        rb = ring_buffer__new(fd, handle_ssl_read, handle_lost_events, NULL);
    }
    
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    // Main event loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
cleanup:
    if (rb) ring_buffer__free(rb);
    if (obj) bpf_object__close(obj);
    if (output_file) fclose(output_file);
    
    printf("\nTracing stopped.\n");
    return 0;
}