# AF_XDP + eBPF Packet Redirection Demo

A minimal demonstration of high-performance packet processing using eBPF XDP and AF_XDP sockets for zero-copy packet transfer between kernel and userspace.

## Overview

This project showcases:
- **eBPF XDP program** running in kernel space that redirects packets
- **AF_XDP socket** in userspace for direct packet reception
- **Zero-copy architecture** bypassing the kernel networking stack
- **Makefile automation** for easy compilation, loading, and testing

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Packet    │     │   eBPF      │     │  Userspace  │
│   arrives   │────▶│  XDP prog   │────▶│  AF_XDP app │
└─────────────┘     └─────────────┘     └─────────────┘
        │                  │                    │
        ▼                  ▼                    ▼
   lo:queue 0      xsks_map[0]=fd      Socket receives
                                      packets directly
```

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install clang llvm libbpf-dev libxdp-dev \
     linux-headers-$(uname -r) bpftool iproute2

# Check dependencies
cd src/uspace && make check-deps
```

#### 1. kpace
```bash
cd kspace
# create a veth-pair iface for test
make add-veth
# for the first call this command will prepare and setup xdp redirect program
make reload-veth
# trace kernel pipe
make trace
```

#### 2. upsace
```bash
cd uspace
make compile
make run-veth
```

#### 3. ping
```bash
cd kpace
make ping-veth
```