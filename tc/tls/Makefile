# Configuration
CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf \
             -D__KERNEL__ \
             -I/usr/include \
             -I/usr/include/x86_64-linux-gnu
VETH0 ?= veth0
VETH1 ?= veth1
VETH0_IP ?= 10.10.0.1
VETH1_IP ?= 10.10.0.2
NET_NS0 ?= ns0
NET_NS1 ?= ns1
NET_NS0_EXEC = ip netns exec $(NET_NS0)
NET_NS1_EXEC = ip netns exec $(NET_NS1)
SUBNET ?= 24

INGRESS_KPROG=kprog.ingress
EGRESS_KPROG=kprog.egress

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

# Настройка namespace и veth
setup-network:
	@echo "$(BLUE)=== Setting up network namespaces ===$(NC)"
	make create-netns
	make create-veth-pair
	make conf-iface
	make bring-up
	make show-status
	@echo "$(GREEN)=== Setup complete ===$(NC)"

create-netns:
	@echo "$(GREEN)Creating namespaces$(NC)"
	sudo ip netns add $(NET_NS0) 2>/dev/null || echo "$(YELLOW)$(NET_NS0) already exists$(NC)"
	sudo ip netns add $(NET_NS1) 2>/dev/null || echo "$(YELLOW)$(NET_NS1) already exists$(NC)"

create-veth-pair:
	@echo "$(GREEN)Creating veth pair$(NC)"
	# Удаляем старую пару если существует
	sudo ip link delete $(VETH0) 2>/dev/null || true
	# Создаем новую пару
	sudo ip link add $(VETH0) type veth peer name $(VETH1)

conf-iface:
	@echo "$(GREEN)Moving interfaces to namespaces$(NC)"
	# Перемещаем интерфейсы в namespace (без IP адресов)
	sudo ip link set $(VETH0) netns $(NET_NS0)
	sudo ip link set $(VETH1) netns $(NET_NS1)
	
	@echo "$(GREEN)Configuring IP addresses$(NC)"
	# Назначаем IP внутри namespace
	sudo $(NET_NS0_EXEC) ip addr add $(VETH0_IP)/$(SUBNET) dev $(VETH0)
	sudo $(NET_NS1_EXEC) ip addr add $(VETH1_IP)/$(SUBNET) dev $(VETH1)

bring-up:
	@echo "$(GREEN)Bringing interfaces up$(NC)"
	# Поднимаем loopback и veth интерфейсы
	sudo $(NET_NS0_EXEC) ip link set lo up
	sudo $(NET_NS0_EXEC) ip link set $(VETH0) up
	
	sudo $(NET_NS1_EXEC) ip link set lo up
	sudo $(NET_NS1_EXEC) ip link set $(VETH1) up

network-status:
	@echo ""
	@echo "$(BLUE)=== $(NET_NS0) interfaces ===$(NC)"
	sudo $(NET_NS0_EXEC) ip addr show
	sudo $(NET_NS0_EXEC) ip route show
	@echo ""
	@echo "$(BLUE)=== $(NET_NS1) interfaces ===$(NC)"
	sudo $(NET_NS1_EXEC) ip addr show
	sudo $(NET_NS1_EXEC) ip route show
	@echo ""

# Очистка
cleanup-network:
	@echo "$(BLUE)=== Cleaning up ===$(NC)"
	sudo ip netns del $(NET_NS0) 2>/dev/null || true
	sudo ip netns del $(NET_NS1) 2>/dev/null || true
	sudo ip link delete $(VETH0) 2>/dev/null || true
	@echo "$(GREEN)Cleanup complete$(NC)"

# Быстрый перезапуск
restart-network:
	make cleanup-network
	make setup-network

# Остальные ваши цели для eBPF
reload-bpf:
	make clean
	make compile
	make unload
	make load

# Загрузка TC eBPF программы
load-bpf:
	# 1. Создаем/заменяем clsact qdisc
	sudo $(NET_NS0_EXEC) tc qdisc add dev $(VETH0) clsact 2>/dev/null || \
	sudo $(NET_NS0_EXEC) tc qdisc replace dev $(VETH0) clsact
	
	# 2. Загружаем программу на ingress
	sudo $(NET_NS0_EXEC) tc filter add dev $(VETH0) ingress bpf da obj $(INGRESS_KPROG).o sec tc/ingress
	
	# 3. Загружаем программу на egress
	sudo $(NET_NS0_EXEC) tc filter add dev $(VETH0) egress bpf da obj $(EGRESS_KPROG).o sec tc/egress
	
	@echo "TC eBPF loaded on $(VETH0) in namespace $(NET_NS0)"

# Выгрузка TC eBPF программы
unload-bpf:
	sudo $(NET_NS0_EXEC) tc qdisc del dev $(VETH0) clsact 2>/dev/null || true
	@echo "TC eBPF unloaded from $(VETH0)"

# Compile eBPF program
compile: $(INGRESS_KPROG).o $(EGRESS_KPROG).o

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Тестирование connectivity
test-network:
	@echo "$(BLUE)=== Testing connectivity ===$(NC)"
	@echo "$(GREEN)Ping from $(NET_NS0) to $(NET_NS1) ($(VETH1_IP))$(NC)"
	sudo $(NET_NS0_EXEC) ping -I $(VETH0) -c 2 $(VETH1_IP) || echo "$(RED)Ping failed$(NC)"
	@echo ""
	@echo "$(GREEN)Ping from $(NET_NS1) to $(NET_NS0) ($(VETH0_IP))$(NC)"
	sudo $(NET_NS1_EXEC) ping -I $(VETH1) -c 2 $(VETH0_IP) || echo "$(RED)Ping failed$(NC)"

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f *.o