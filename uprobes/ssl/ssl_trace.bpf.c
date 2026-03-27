// ssl_write_minimal.bpf.c - Minimal SSL_write tracer
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "/usr/include/x86_64-linux-gnu/asm/ptrace.h"

char LICENSE[] SEC("license") = "GPL";

// Store arguments for return probe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} buf_map SEC(".maps");

// Entry probe - capture buffer pointer
SEC("uprobe//usr/lib/x86_64-linux-gnu/libssl.so:SSL_write")
int trace_ssl_write_entry(struct pt_regs *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 buf_ptr = PT_REGS_PARM2(ctx);  // second argument is buffer
    
    // Store buffer pointer for return probe
    bpf_map_update_elem(&buf_map, &tid, &buf_ptr, BPF_ANY);
    return 0;
}

// Return probe - capture data
SEC("uretprobe//usr/lib/x86_64-linux-gnu/libssl.so:SSL_write")
int trace_ssl_write_return(struct pt_regs *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    int ret = PT_REGS_RC(ctx);  // return value = bytes written
    
    if (ret <= 0) return 0;
    
    // Get stored buffer pointer
    __u64 *buf_ptr = bpf_map_lookup_elem(&buf_map, &tid);
    if (!buf_ptr) return 0;

    __u64 len = ret;
    bpf_printk("len=%d, buf=%p", len, buf_ptr);
    return 0;
}