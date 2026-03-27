CC = gcc
CLANG = clang

CFLAGS = -Wall -O2 -g
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf -lelf -lz

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

KPROG = ssl_trace.bpf.o

attach:
	PROG_ID=1

	# Load your eBPF program
	sudo bpftool prog load $(KPROG).o /sys/fs/bpf/ssl_trace

	# List loaded programs to get the program IDs
	sudo bpftool prog list | grep -A 5 ssl_write

	# Attach the uprobe (replace PROG_ID with actual ID from above)
	# For entry probe:
	sudo bpftool prog attach $(PROG_ID) uprobe /usr/lib/x86_64-linux-gnu/libssl.so SSL_write

	# For return probe (different PROG_ID):
	sudo bpftool prog attach PROG_ID_RET uprobe /usr/lib/x86_64-linux-gnu/libssl.so SSL_write

	# Check if attached
	sudo bpftool prog list

compile: $(KPROG).o


$(KPROG).o: $(KPROG).c
	$(CLANG) $(BPF_CFLAGS) -g -O2 -c $< -o $@

trace:
	# Read trace_pipe to see bpf_printk output
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(BPF_OBJ) *.o *.log
