# Configuration
CLANG ?= clang
VETH0 ?= veth0
VETH1 ?= veth1
VETH0_IP ?= 10.10.0.1
VETH1_IP ?= 10.10.0.2
NET_NS0 ?= ns0
NET_NS1 ?= ns1
SUBNET ?= 24
BRIDGE ?= br-veth
PHYSICAL_IFACE ?= $(shell ip route | grep default | awk '{print $$5}' | head -1)

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

BPF_MOUNT ?= /sys/fs/bpf
PROG_NAME ?= icmp_echo
MAP_NAME ?= xsks_map


# Compilation flags
BPF_CFLAGS = -O2 -target bpf -g -Xclang -disable-llvm-passes

# Compile eBPF program
compile: icmp_echo.o dummy.o

$(PROG_NAME).o: $(PROG_NAME).c
	$(CLANG) -O2 -target bpf -c $(PROG_NAME).c -o $(PROG_NAME).o

dummy.o: dummy.c
	$(CLANG) -O2 -target bpf -c dummy.c -o dummy.o

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

load:
	sudo ip netns exec $(NET_NS0) ip link set dev $(VETH0) xdp obj $(PROG_NAME).o sec xdp
	sudo ip netns exec $(NET_NS1) ip link set dev $(VETH1) xdp obj dummy.o sec xdp

unload:
	sudo ip netns exec $(NET_NS0) ip link set dev $(VETH0) xdp off > /dev/null 2> /dev/null
	sudo ip netns exec $(NET_NS1) ip link set dev $(VETH1) xdp off > /dev/null 2> /dev/null

reload:
	make unload
	make clean
	make compile
	make load

# Full cleanup
clean:
	rm -f *.o
	@echo "✅ Full cleanup complete"

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

ping:
	sudo ip netns exec $(NET_NS1) ping -I $(VETH1) $(VETH0_IP) -c 1

# Clean BPF objects before load (simplified)
clean-bpf:
	@echo "Cleaning old objects..."
	# 1. Detach from interface
	-sudo ip link set dev $(INTERFACE) xdp off 2>/dev/null
	-sudo bpftool net detach xdp dev $(INTERFACE) 2>/dev/null
	
	# 2. Remove files (usually enough)
	-sudo rm -f $(BPF_MOUNT)/$(PROG_NAME) $(BPF_MOUNT)/$(MAP_NAME) 2>/dev/null
	
	# 3. Try to remove program (optional)
	@PROG_ID=$$(sudo bpftool prog show 2>/dev/null | awk '/xdp_redirect_all/ {print $$1}' | cut -d: -f1 | head -1); \
	if [ -n "$$PROG_ID" ]; then \
		echo "   Removing program ID: $$PROG_ID"; \
		sudo bpftool prog destroy id $$PROG_ID 2>/dev/null || true; \
	fi
	
	# 4. Try to remove map (optional)
	@MAP_ID=$$(sudo bpftool map show 2>/dev/null | awk '/xsks_map/ {print $$1}' | cut -d: -f1 | head -1); \
	if [ -n "$$MAP_ID" ]; then \
		echo "   Removing map ID: $$MAP_ID"; \
		sudo bpftool map delete id $$MAP_ID key 0 0 0 0 2>/dev/null || true; \
	fi
	
	@echo "   Cleanup complete"

.PHONY: all compile load pin unpin clean-bpf check unload clean help