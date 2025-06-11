cmake_minimum_required(VERSION 3.14)
project(xdp_stat)

set(CMAKE_C_STANDARD 11)

# Путь к заголовкам libbpf
include_directories(/usr/include/libbpf)

add_executable(xdp_stat xdp_stat.cpp)

target_link_libraries(xdp_stat
    PRIVATE
        bpf
        elf
        z
)