# Configuration
CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf \
             -D__KERNEL__ \
             -I/usr/include \
             -I/usr/include/x86_64-linux-gnu
CXXFLAGS = -std=c++17 -Wall -g
LDFLAGS = -lstdc++ -lbpf -lpthread -lelf -lz

KPROG=kprog
UPROG=uspace


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

	@# Create veth pair
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

	@# ===== УНИВЕРСАЛЬНОЕ РЕШЕНИЕ =====
	@# Это правило работает ВСЕГДА, независимо от VPN
	@# Оно маскарадит ВЕСЬ трафик из namespace, КРОМЕ возвращающегося через veth1
	sudo iptables -t nat -A POSTROUTING -s $(NETWORK) -j MASQUERADE

	@# Разрешаем форвардинг для veth1
	sudo iptables -A FORWARD -i $(VETH1) -j ACCEPT
	sudo iptables -A FORWARD -o $(VETH1) -j ACCEPT

	@# Разрешаем установленные соединения
	sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

	@# Настройка DNS для namespace
	sudo mkdir -p /etc/netns/$(NET_NS)
	echo "nameserver 8.8.8.8" | sudo tee /etc/netns/$(NET_NS)/resolv.conf > /dev/null
	echo "nameserver 1.1.1.1" | sudo tee -a /etc/netns/$(NET_NS)/resolv.conf > /dev/null

	@# Определяем, какой интерфейс используется для интернета
	$(eval DEFAULT_IFACE := $(shell ip route | grep default | awk '{print $$5}' | head -1))

	@echo ""
	@echo "✓ Setup complete"
	@echo "  Namespace: $(NET_NS) = $(VETH2_IP)"
	@echo "  Host veth: $(VETH1) = $(VETH1_IP)"
	@echo "  Default interface: $(DEFAULT_IFACE)"
	@echo ""
	@echo "Test: make test-network"

cleanup-network:
	@# Удаляем универсальное правило NAT
	-sudo iptables -t nat -D POSTROUTING -s $(NETWORK) -j MASQUERADE 2>/dev/null

	@# Удаляем правила FORWARD
	-sudo iptables -D FORWARD -i $(VETH1) -j ACCEPT 2>/dev/null
	-sudo iptables -D FORWARD -o $(VETH1) -j ACCEPT 2>/dev/null
	-sudo iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

	@# Удаляем namespace
	-sudo ip netns delete $(NET_NS) 2>/dev/null

	@# Удаляем veth интерфейс
	-sudo ip link delete $(VETH1) 2>/dev/null

	@# Удаляем DNS настройки
	-sudo rm -rf /etc/netns/$(NET_NS) 2>/dev/null

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
	sudo tc filter add dev $(VETH1) ingress bpf da obj $(KPROG).o sec tc/ingress
	
	@echo "TC eBPF loaded on $(VETH1)"

# Выгрузка TC eBPF программы
unload-bpf:
	sudo tc qdisc del dev $(VETH1) clsact 2>/dev/null || true
	@echo "TC eBPF unloaded from $(VETH1)"

# Compile eBPF program
compile: $(KPROG).o $(UPROG)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(UPROG): $(UPROG).cpp
	g++ -g $(CXXFLAGS) client_hello.cpp -o $@ $^ $(LDFLAGS)

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f *.o $(UPROG)