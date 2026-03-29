# Configuration
CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf \
             -D__KERNEL__ \
             -I/usr/include \
             -I/usr/include/x86_64-linux-gnu
INGRESS_KPROG=kprog.ingress
EGRESS_KPROG=kprog.egress


NET_NS := test_ns
VETH1 := veth1
VETH2 := veth2
VETH1_IP := 10.10.0.1
VETH2_IP := 10.10.0.2
NETMASK := 24
NETWORK := 10.10.0.0/24
NET_NS_EXEC = ip netns exec $(NET_NS)

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

tcp-dump-$(VETH2):
	sudo $(NET_NS_EXEC) tcpdump -i $(VETH2) -vv tcp

tcp-dump-$(VETH1):
	sudo tcpdump -i $(VETH1) -vv tcp


tcp-ping:
	#echo "hello world" | nc -s 10.10.0.1 -p 12345 10.10.0.2 9999
	python tcp-sender.py --src-ip $(VETH1_IP) --dst-ip $(VETH2_IP) --src-port 1234 --dst-port 4321 --message "Hello wold"

tcp-echo-server:
	#sudo ip netns exec test_ns ncat -l -p 9999 -k -c 'cat'
	sudo $(NET_NS_EXEC) python tcp-server.py --port 4321

https-test:
	sudo $(NET_NS_EXEC) curl https://example.com  #https://cppreference.com

setup-network:
	@# Check if namespace already exists
	@if sudo ip netns exec $(NET_NS) true 2>/dev/null; then \
		echo "ERROR: namespace $(NET_NS) already exists" >&2; \
		exit 1; \
	fi
	@# Create namespace
	sudo ip netns add $(NET_NS)
	@# Create veth pair with one end in namespace
	sudo ip link add $(VETH1) type veth peer name $(VETH2) netns $(NET_NS)
	@# Configure host side
	sudo ip addr add $(VETH1_IP)/$(NETMASK) dev $(VETH1)
	sudo ip link set $(VETH1) up
	@# Configure namespace side
	sudo ip -n $(NET_NS) addr add $(VETH2_IP)/$(NETMASK) dev $(VETH2)
	sudo ip -n $(NET_NS) link set $(VETH2) up
	sudo ip -n $(NET_NS) route add default via $(VETH1_IP)
	@# Enable IP forwarding
	echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
	@# Add NAT (exclude traffic going out veth1 to avoid loop)
	sudo iptables -t nat -A POSTROUTING -s $(NETWORK) ! -o $(VETH1) -j MASQUERADE
	@echo ""
	@echo "✓ veth pair setup complete"
	@echo "  Host: $(VETH1) = $(VETH1_IP)"
	@echo "  Namespace: $(NET_NS) = $(VETH2_IP) (via $(VETH2))"
	@echo ""
	@echo "Test: sudo ip netns exec $(NET_NS) ping 8.8.8.8"

cleanup-network:
	@# Remove iptables rules (ignore if they don't exist)
	-sudo iptables -t nat -D POSTROUTING -s $(NETWORK) ! -o $(VETH1) -j MASQUERADE 2>/dev/null
	@# Delete namespace (ignore if it doesn't exist)
	-sudo ip netns delete $(NET_NS) 2>/dev/null
	@# Clean up host veth if needed
	-sudo ip link delete $(VETH1) 2>/dev/null
	@echo "✓ Cleanup complete"

status:
	@echo "=== Namespace ==="
	@sudo ip netns list | grep $(NET_NS) || echo "Namespace not found"
	@echo ""
	@echo "=== Host $(VETH1) ==="
	@sudo ip addr show $(VETH1) 2>/dev/null || echo "veth not found"
	@echo ""
	@echo "=== Namespace interfaces ==="
	@sudo ip -n $(NET_NS) addr show 2>/dev/null || echo "Cannot access namespace"
	@echo ""
	@echo "=== Routes in namespace ==="
	@sudo ip -n $(NET_NS) route show 2>/dev/null || echo "No routes"
	@echo ""
	@echo "=== IP Forwarding ==="
	@cat /proc/sys/net/ipv4/ip_forward


# Тестирование connectivity
test-network:
	@echo "$(BLUE)=== Testing connectivity ===$(NC)"
	sudo $(NET_NS_EXEC) ping 8.8.8.8 -c 2
	sudo $(NET_NS_EXEC) ping -I $(VETH2) $(VETH1_IP) -c 2


# Быстрый перезапуск
restart-network:
	make cleanup-network
	make setup-network

# Остальные ваши цели для eBPF
reload-bpf:
	make clean
	make compile
	make unload-bpf
	make load-bpf

# Загрузка TC eBPF программы
load-bpf:
	# 1. Создаем/заменяем clsact qdisc
	sudo tc qdisc add dev $(VETH1) clsact 2>/dev/null || \
	sudo tc qdisc replace dev $(VETH1) clsact
	
	# 2. Загружаем программу на ingress
	sudo tc filter add dev $(VETH1) ingress bpf da obj $(INGRESS_KPROG).o sec tc/ingress
	
	# 3. Загружаем программу на egress
	sudo tc filter add dev $(VETH1) egress bpf da obj $(EGRESS_KPROG).o sec tc/egress
	
	@echo "TC eBPF loaded on $(VETH1)"

# Выгрузка TC eBPF программы
unload-bpf:
	sudo tc qdisc del dev $(VETH1) clsact 2>/dev/null || true
	@echo "TC eBPF unloaded from $(VETH1)"

# Compile eBPF program
compile: $(INGRESS_KPROG).o $(EGRESS_KPROG).o

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f *.o