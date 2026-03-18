#include <linux/bpf.h>      // Basic eBPF definitions and types
#include <linux/if_ether.h> // Ethernet protocol definitions
#include <bpf/bpf_helpers.h> // eBPF helper functions

// License declaration - mandatory for eBPF programs
// Kernel verifier checks this to ensure GPL compatibility
char LICENSE[] SEC("license") = "GPL";

// Define an XSKMAP (AF_XDP socket map) for redirecting packets to userspace
// This map type is specifically designed for AF_XDP socket redirection
struct {
    // Map type: BPF_MAP_TYPE_XSKMAP (value 17)
    // Special map type that stores file descriptors of AF_XDP sockets
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    
    // Maximum number of entries (RX queues) the map can hold
    // Each entry corresponds to one RX queue (0-63)
    __uint(max_entries, 64);
    
    // Key size: 4 bytes (32-bit unsigned integer)
    // Key represents the RX queue index (0, 1, 2, ...)
    __uint(key_size, sizeof(__u32));
    
    // Value size: 4 bytes (32-bit unsigned integer)
    // Value is the file descriptor of the AF_XDP socket
    __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");  // Place in special ".maps" ELF section

// XDP (eXpress Data Path) program section
// This function is called for every packet received on the interface
SEC("xdp")
int xdp_redirect_all(struct xdp_md *ctx)
{
    // Extract RX queue index from the packet context
    // Each network interface can have multiple RX queues for parallel processing
    __u32 index = (__u32)ctx->rx_queue_index;
    
    // Safety check: ensure queue index is within map bounds
    // If index >= 64, pass the packet to normal kernel network stack
    if (index >= 64)
        return XDP_PASS;  // Let packet continue through normal network stack
    
    // Debug output - writes to kernel trace buffer
    // Can be viewed with: sudo cat /sys/kernel/debug/tracing/trace_pipe
    // Note: In production, remove or conditionalize this for performance
    bpf_printk("XDP program received a packet, RX index=%d\n", index);
    
    // Redirect packet to AF_XDP socket using the XSKMAP
    // Parameters:
    //   &xsks_map - pointer to our XSKMAP
    //   index     - key to look up (RX queue index)
    //   0         - flags (no special flags)
    //
    // What happens:
    // 1. Look up xsks_map[index] to get AF_XDP socket file descriptor
    // 2. If socket exists: packet goes directly to userspace via that socket
    // 3. If socket doesn't exist: returns XDP_ABORTED (should handle gracefully)
    // 4. On success: returns XDP_REDIRECT
    int ret = bpf_redirect_map(&xsks_map, index, 0);
    if (ret == XDP_REDIRECT) {
        bpf_printk("Redirect SUCCESS to socket in xsks_map[%d]\n", index);
        return XDP_REDIRECT;
    } else {
        bpf_printk("Redirect failed (code=%d), passing packet\n", ret);
        return XDP_PASS;
    }
}

// How this works with userspace:
// 1. Userspace creates an AF_XDP socket bound to a specific queue
// 2. Userspace inserts socket FD into xsks_map at key = queue index
// 3. When packet arrives on that queue, XDP program redirects it to the socket
// 4. Userspace receives packet via AF_XDP socket, bypassing kernel network stack
//
// Performance benefits:
// - Zero-copy: packets go directly from NIC to userspace
// - Bypasses kernel networking stack
// - Very low latency (microseconds)
//
// Typical use cases:
// - High-performance packet processing
// - DDoS protection
// - Load balancers
// - Network monitoring
//
// Important notes:
// - Program runs in kernel context - must be safe and verifiable
// - Limited to 1 million instructions per packet
// - No loops (except bounded), no blocking operations
// - Must pass kernel verifier checks
