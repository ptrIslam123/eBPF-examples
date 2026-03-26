# Configuration
CLANG ?= clang
VETH0 ?= veth0
VETH1 ?= veth1
VETH0_IP ?= 10.10.0.1
VETH1_IP ?= 10.10.0.2
NET_NS0 ?= ns0
NET_NS1 ?= ns1
NET_NS0_EXEC = ip netns exec $(NET_NS0)
NET_NS1_EXEC = ip netns exec $(NET_NS1)
SUBNET ?= 24
BRIDGE ?= br-veth

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

INTERFACE ?= $(VETH0)
BPF_MOUNT ?= /sys/fs/bpf
INGRESS_KPROG = kprog.ingress
EGRESS_KPROG = kprog.egress
MAP_NAME ?= xsks_map

BPF_CFLAGS = -O2 -g -Wall -target bpf \
             -D__KERNEL__ \
             -I/usr/include \
             -I/usr/include/x86_64-linux-gnu

reload:
	make clean
	make compile
	make unload
	make load

# Загрузка TC eBPF программы
load:
	# 1. Создаем/заменяем clsact qdisc (обязательно для TC)
	sudo ip netns exec $(NET_NS0) tc qdisc add dev $(VETH0) clsact 2>/dev/null || \
	sudo ip netns exec $(NET_NS0) tc qdisc replace dev $(VETH0) clsact
	
	# 2. Загружаем программу на ingress (входящие пакеты)
	sudo ip netns exec $(NET_NS0) tc filter add dev $(VETH0) ingress bpf da obj $(INGRESS_KPROG).o sec tc/ingress
	
	# 3. Загружаем программу на egress (исходящие пакеты)
	sudo ip netns exec $(NET_NS0) tc filter add dev $(VETH0) egress bpf da obj $(EGRESS_KPROG).o sec tc/egress
	
	@echo "TC eBPF loaded on $(VETH0) in namespace $(NET_NS0)"
	@echo "  Ingress: tc/ingress"
	@echo "  Egress:  tc/egress"

# Выгрузка TC eBPF программы
unload:
	# Удаляем весь clsact qdisc (очищает все фильтры)
	sudo ip netns exec $(NET_NS0) tc qdisc del dev $(VETH0) clsact 2>/dev/null || true
	@echo "TC eBPF unloaded from $(VETH0)"

setup:
	make add-veth
	make add-netns

add-netns:
	# Create two namespace
	sudo ip netns add $(NET_NS0)
	sudo ip netns add $(NET_NS1)

	# Move interfaces to namespace
	sudo ip link set $(VETH0) netns $(NET_NS0)
	sudo ip link set $(VETH1) netns $(NET_NS1)

	# Up namespace
	sudo ip netns exec $(NET_NS0) ip link set $(VETH0) up
	sudo ip netns exec $(NET_NS1) ip link set $(VETH1) up

	# Setup IP
	sudo ip netns exec $(NET_NS0) ip addr add $(VETH0_IP)/$(SUBNET) dev $(VETH0)
	sudo ip netns exec $(NET_NS1) ip addr add $(VETH1_IP)/$(SUBNET) dev $(VETH1)

remove-netns:
	sudo ip netns del $(NET_NS0)
	sudo ip netns del $(NET_NS1)

# Setup veth pair and network
add-veth:
	@echo "$(BLUE)=== Setting up veth pair ===$(NC)"

	# 1. Check if veth already exists
	@if ip link show $(VETH0) >/dev/null 2>&1; then \
		echo "$(YELLOW)Warning: $(VETH0) already exists$(NC)"; \
		echo "Run 'make cleanup' first or use different names"; \
		exit 1; \
	fi

	# 2. Create veth pair
	@echo "$(GREEN)Creating veth pair: $(VETH0) <--> $(VETH1)$(NC)"
	sudo ip link add $(VETH0) type veth peer name $(VETH1)

	# 3. Bring interfaces up
	@echo "$(GREEN)Bringing interfaces up$(NC)"
	sudo ip link set $(VETH0) up
	sudo ip link set $(VETH1) up

	# 4. Assign IP addresses
	@echo "$(GREEN)Assigning IP addresses$(NC)"
	sudo ip addr add $(VETH0_IP)/$(SUBNET) dev $(VETH0)
	sudo ip addr add $(VETH1_IP)/$(SUBNET) dev $(VETH1)

	# 5. Disable IPv6 (optional, reduces noise)
	@echo "$(GREEN)Disabling IPv6 on veth interfaces$(NC)"
	echo 1 | sudo tee /proc/sys/net/ipv6/conf/$(VETH0)/disable_ipv6 >/dev/null
	echo 1 | sudo tee /proc/sys/net/ipv6/conf/$(VETH1)/disable_ipv6 >/dev/null

	# 6. Configure routing (optional)
	@echo "$(GREEN)Adding route to veth network$(NC)"
	sudo ip route add 10.10.0.0/24 dev $(VETH0) || true

	# 7. Show configuration
	@echo ""
	@echo "$(GREEN)=== Setup Complete ===$(NC)"
	@echo "$(VETH0): $(VETH0_IP)/$(SUBNET)"
	@echo "$(VETH1): $(VETH1_IP)/$(SUBNET)"
	@echo ""
	@echo "Use 'make status' to verify configuration"
	@echo "Use 'make test' to test connectivity"
	@echo "Use 'make cleanup' to remove veth pair"

# Cleanup - remove veth pair
remove-veth:
	@echo "$(BLUE)=== Cleaning up veth configuration ===$(NC)"

	# Remove from bridge if bridged
	@if ip link show $(VETH0) 2>/dev/null | grep -q "master"; then \
		echo "$(GREEN)Removing $(VETH0) from bridge$(NC)"; \
		sudo ip link set $(VETH0) nomaster; \
	fi

	# Delete bridge if empty
	@if ip link show type bridge 2>/dev/null | grep -q "$(BRIDGE)"; then \
		echo "$(GREEN)Removing bridge $(BRIDGE)$(NC)"; \
		sudo ip link delete $(BRIDGE) type bridge; \
	fi

	# Delete veth interfaces (deleting one deletes both)
	@if ip link show $(VETH0) >/dev/null 2>&1; then \
		echo "$(GREEN)Deleting veth pair $(VETH0) <--> $(VETH1)$(NC)"; \
		sudo ip link delete $(VETH0); \
	else \
		echo "$(YELLOW)$(VETH0) not found$(NC)"; \
	fi

	# Cleanup network namespaces
	@echo "$(GREEN)Cleaning up test network namespaces$(NC)"
	sudo ip netns delete test-ns 2>/dev/null || true

	# Remove routes
	@echo "$(GREEN)Cleaning up routes$(NC)"
	sudo ip route del 10.10.0.0/24 dev $(VETH0) 2>/dev/null || true

	@echo "$(GREEN)Cleanup complete$(NC)"


# Compile eBPF program
compile: $(INGRESS_KPROG).o $(EGRESS_KPROG).o

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

ping:
	sudo $(NET_NS1_EXEC) ping $(VETH0_IP) -c 2

udp-ping:
	echo "hello world" | sudo ip netns exec $(NET_NS1) nc -u $(VETH0_IP) 12345 -w 1

udp-tcpdum:
	sudo ip netns exec $(NET_NS1) tcpdump -i any -A -vv udp -l
