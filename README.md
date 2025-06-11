### env set up:

```bash
sudo apt install clang llvm libelf-dev libbpf-dev build-essential
```

### compilation:

```bash
clang -O2 -Wall -target bpf -I/usr/include/$(uname -r) -I/usr/include/x86_64-linux-gnu -c ebpf_program.c -o ebpf_program.o
```

### link:

* load with iproute2:

```bash
sudo ip link set dev <интерфейс> xdp obj <ebpf_program.o> sec xdp 
```

Example:

```bash
sudo ip link set dev wlp43s0 xdp obj ebpf_program.o sec xdp
```

* check program loading:

```bash
ip link show <интерфейс>
```

Example:

```bash
ip link show wlp43s0
```

### check program progress:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### unload with iproute2:

```bash
sudo ip link set dev <интерфейс> xdp off
```

Example:

```bash
sudo ip link set dev wlp43s0 xdp off 
```
