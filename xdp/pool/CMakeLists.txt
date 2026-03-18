cmake_minimum_required(VERSION 3.14)
set(UNIT_NAME xdp_pool)
project(${UNIT_NAME})

set(CMAKE_C_STANDARD 11)

add_executable(${UNIT_NAME} ${UNIT_NAME}.cpp)

target_include_directories(${UNIT_NAME} PUBLIC /usr/include/libbpf)

target_link_libraries(${UNIT_NAME}
    PRIVATE
        bpf
        elf
        z
)