# AF_XDP + eBPF Packet Redirection Demo

A minimal demonstration of high-performance packet processing using eBPF XDP and AF_XDP sockets for zero-copy packet transfer between kernel and userspace.

## 📋 Overview

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

### 1. Load eBPF Program
```bash
cd src/kspace
make all              # Compile and load eBPF program
make check           # Verify everything loaded correctly
```

### 2. Run Userspace Application
```bash
cd src/uspace
make run            # Compile and run AF_XDP app
```

### 3. Generate Test Traffic
```bash
# In another terminal
ping -c 3 127.0.0.1
```
