// ssl_trace.h - Shared definitions with proper types
#ifndef __SSL_TRACE_H
#define __SSL_TRACE_H

#include <linux/types.h>
#include <stdint.h>

#define MAX_STR_LEN 256
#define MAX_DATA_LEN 4096
#define MAX_COMM_LEN 16

// Event structure for SSL_write calls
struct ssl_write_event {
    uint32_t pid;
    uint32_t tid;
    uint64_t timestamp;
    char comm[MAX_COMM_LEN];
    uint64_t ssl_ptr;        // SSL* pointer
    uint64_t buf_ptr;        // buffer pointer
    int num_bytes;           // requested write size
    int ret_value;           // return value (actual bytes written)
    char data[MAX_DATA_LEN]; // captured data (truncated)
    int data_len;            // actual captured data length
};

// Event structure for SSL_read calls
struct ssl_read_event {
    uint32_t pid;
    uint32_t tid;
    uint64_t timestamp;
    char comm[MAX_COMM_LEN];
    uint64_t ssl_ptr;        // SSL* pointer
    uint64_t buf_ptr;        // buffer pointer
    int num_bytes;           // requested read size
    int ret_value;           // return value (actual bytes read)
    char data[MAX_DATA_LEN]; // captured data (truncated)
    int data_len;            // actual captured data length
};

#endif