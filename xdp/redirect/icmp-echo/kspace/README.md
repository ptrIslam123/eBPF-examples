# XDP ICMP Echo Responder

A high-performance eBPF/XDP program that responds to ICMP echo requests (pings) directly in the XDP layer, without involving the kernel network stack.

## Overview

This project implements an XDP (eXpress Data Path) program that:
- Intercepts ICMP echo requests (ping) at the earliest possible point in the network stack
- Swaps source/destination IP and MAC addresses
- Transforms ICMP echo requests into echo replies
- Returns packets directly via `XDP_TX` for minimal latency
- Achieves sub-microsecond response times

## Architecture

The program is attached to a virtual interface (veth pair) and processes packets before they reach the kernel network stack, providing ultra-fast ICMP response capabilities.

## Prerequisites

- Linux kernel 5.4+
- LLVM/clang 10+
- libbpf development libraries
- iproute2
- bpftool

## How It Works

1. **Packet Reception**: The XDP program attached to `veth-host` intercepts all incoming packets
2. **ICMP Detection**: Identifies ICMP echo requests (type 8)
3. **Address Swapping**: 
   - Swaps source/destination IP addresses
   - Swaps source/destination MAC addresses
4. **Type Conversion**: Changes ICMP type from 8 (echo request) to 0 (echo reply)
5. **Direct Return**: Returns packet via `XDP_TX` - sends it back through the same interface

## Quick Start

### 1. Terminal 1 - Setup and Monitor
```bash
# Compile the XDP program
make compile

# Create veth pair and network namespace
make add-veth

# Enter target network namespace
make add-netns

# Monitor XDP traces (in namespace)
make trace
```

### 2. Terminal 2 - Test
```bash
# Send ping from default namespace to target namespace
make ping
```

## Cleanup

```bash
make remove-veth  # Remove virtual interfaces
make remove-netns
make clean     # Clean build artifacts
```

Expected output:
```
make ping
sudo ip netns exec ns1 ping -I veth1 10.10.0.1 -c 1
PING 10.10.0.1 (10.10.0.1) from 10.10.0.2 veth1: 56(84) bytes of data.
64 bytes from 10.10.0.1: icmp_seq=1 ttl=64 time=0.044 ms

--- 10.10.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.044/0.044/0.044/0.000 ms

```
