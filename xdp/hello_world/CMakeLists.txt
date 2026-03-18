cmake_minimum_required(VERSION 3.14)
SET(UNIT_NAME xdp_hello_world)
project(${UNIT_NAME})

add_executable(${UNIT_NAME} ${UNIT_NAME}.cpp)

target_include_directories(${UNIT_NAME} PUBLIC /usr/include/libbpf)

target_link_libraries(${UNIT_NAME}
PRIVATE
bpf
elf
z
)