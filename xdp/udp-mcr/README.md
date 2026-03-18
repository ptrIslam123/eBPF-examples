# AF_XDP MCR Packet Processor

This mini-project demonstrates **AF_XDP** (Address Family eXpress Data Path) - a technology for high-performance network packet processing that bypasses the Linux kernel stack.

Show how to intercept UDP packets at the lowest level (NIC → XDP → AF_XDP socket) and process them in userspace with minimal latency.

## Work flow

1. **Captures UDP packets** directly from the network interface (physical or virtual)
2. **Parses Ethernet/IP/UDP headers** in userspace
3. **Processes packets** through MCR (MITIGATOR Challenge Response) logic https://docs.mitigator.ru/v25.02/integrate/mcr/
4. **All without touching** the traditional Linux network stack

## Architecture

```
Network Packet → NIC → XDP/eBPF → AF_XDP Socket → Userspace App
                      ↓                              ↓
                Bypasses kernel                 MCR Processing
                network stack
```

## Why AF_XDP?

- **Zero-copy** - packets go directly from NIC to userspace
- **No kernel overhead** - bypasses TCP/IP stack
- **Line-rate processing** - millions of packets per second
- **Flexible** - process packets in userspace with normal C/C++ code


## Quick Demo
**The demo uses virtual Ethernet interfaces and network namespaces to create an isolated test environment**

```bash
# 1. Create virtual test environment
make add-veth
make add-netns

# 2. Load XDP/AF_XDP program
make load

# 3. Send test UDP packet
make mcr-test

# 4. Watch packet processing
# Program shows: received packet → parsed UDP → MCR processed

# 5. Cleanup env
make remove-veth
make remove-netns
make clean
```
