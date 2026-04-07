#include "client_hello.h"

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <atomic>
#include <iostream>
#include <iomanip>

#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <netinet/in.h>

extern "C" {
    #include <bpf/bpf.h>
    #include <bpf/libbpf.h>
    //#include "tls_handler.h"
}

struct tls_data {
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

typedef struct tls_server_hello {
    /* Part 1: Fixed fields */
    __u16 server_version;           // offset 0-1: chosen TLS version
    
    /* Part 2: Random (32 bytes) */
    __u8  random[32];               // offset 2-33: server random
    
    /* Part 3: Session ID */
    __u8  session_id_len;           // offset 34: length of session ID
    __u8* session_id;               // variable: session ID
    
    /* Part 4: Chosen parameters */
    __u16 cipher_suite;             // chosen cipher suite (2 bytes)
    __u8  compression_method;       // chosen compression method
    
    /* Part 5: Extensions (optional, TLS 1.3 requires them) */
    __u16 extensions_len;           // may be present
    __u8* extensions;               // variable: TLS extensions
} __attribute__((packed)) tls_server_hello_t;

void HandleTLS(uint8_t* data, uint64_t len) {
    struct tls_data* metadata = (struct tls_data*)data;
    
    std::cout << "TLS Record Type: " << (int)metadata->tls_record_type;
    if (metadata->tls_record_type == 22) std::cout << " (Handshake)";
    std::cout << "\n";
    std::cout << "Record Length: " << ntohs(metadata->tls_record_len) << "\n";
    
    tls::ClientHelloContext chc{(__u8*)((struct tls_data*)data + 1), len};
    std::cout << chc << std::endl;
}

std::atomic<bool> IsRunning{true};

void SignalHandler(int sig) {
    IsRunning.store(false);
}

void Usage(int argc, char **argv) {
    std::exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        Usage(argc, argv);
    }

    std::string iface;
    std::string file;
    std::string map;
    {
        constexpr auto npos = std::string_view::npos;
        for (auto i = 1; i < argc; ++i) {
            constexpr std::string_view IFACE{"--iface="};
            constexpr std::string_view FILE{"--file="};
            constexpr std::string_view MAP{"--map="};

            std::string_view arg{argv[i]};
            auto s = npos;
            if (s = arg.find(IFACE); s != npos) {
                iface = arg.substr(s + IFACE.size());
                continue;
            } else if (s = arg.find(FILE); s != npos) {
                file = arg.substr(s + FILE.size());
            } else if (s = arg.find(MAP); s != npos) {
                map = arg.substr(s + MAP.size());
            } else {
                std::cerr << "Unknown arg: " << arg << std::endl;
                Usage(argc, argv);
            }
        }
    }

    printf("Using interface: %s\n", iface.c_str());
    printf("Using BPF file: %s\n", file.c_str());
    printf("Map: %s\n", map.c_str());


    // Настройка обработчика сигналов
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    int mapfd{-1};
    {
        __u32 map_id{0};
        while (true) {
            __u32 next_id;
            if (bpf_map_get_next_id(map_id, &next_id) != 0) {
                break;
            }

            map_id = next_id;
            int fd = bpf_map_get_fd_by_id(map_id);
            if (fd < 0) {
                continue;
            }

            struct bpf_map_info info = {};
            __u32 info_len = sizeof(info);
            if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
                if (strcmp(info.name, "tls_events") == 0) {
                    mapfd = fd;
                    break;
                }
            }
            close(fd);
        }
    }
    
    if (mapfd < 0) {
        fprintf(stderr, "Map \'%s\' not found!\n", map.c_str());
        return 1;
    }

    printf("Got map fd: %d\n", mapfd);
    
    auto page_size = sysconf(_SC_PAGE_SIZE);
    struct bpf_map_info info = {};
    __u32 infolen = sizeof(info);
    if (bpf_obj_get_info_by_fd(mapfd, &info, &infolen) < 0) {
        perror("bpf_obj_get_info_by_fd");
        close(mapfd);
        return 1;
    }
    
    __u64 rb_sz = info.max_entries;
    printf("Ring buffer size: %llu bytes\n", rb_sz);
    
    // mmap consumer page
    void *consumer_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, mapfd, 0);
    if (consumer_page == MAP_FAILED) {
        perror("mmap consumer");
        close(mapfd);
        return 1;
    }
    
    // mmap data area (double mapped)
    __u64 mmap_sz = page_size + 2 * rb_sz;
    void *data_area = mmap(NULL, mmap_sz, PROT_READ, MAP_SHARED,
                           mapfd, page_size);
    if (data_area == MAP_FAILED) {
        perror("mmap data");
        munmap(consumer_page, page_size);
        close(mapfd);
        return 1;
    }
    
    __u64 *consumer = (__u64 *)consumer_page;
    __u64 *producer = (__u64 *)data_area;
    
    printf("Waiting for events... Press Ctrl+C to stop\n\n");
    
    while (IsRunning.load()) {
        __u64 cons = *consumer;
        __u64 prod = *producer;
        
        while (cons < prod) {
            __u32 *header = (__u32 *)((char *)data_area + page_size + (cons % rb_sz));
            __u32 len = *header & 0x3FFFFFFF;
            __u32 flags = (*header >> 30) & 0x3;
            
            if (!(flags & 0x1)) {
                auto sample = (__u8*)data_area + page_size + ((cons + 8) % rb_sz);
                HandleTLS(sample, len);
            }
            
            cons += 8 + len;
            cons = (cons + 7) & ~7;
        }
        
        __sync_synchronize();
        *consumer = cons;
        
        usleep(10000);
    }
    
    munmap(data_area, mmap_sz);
    munmap(consumer_page, page_size);
    close(mapfd);
    return EXIT_SUCCESS;
}