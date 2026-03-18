# Configuration
CLANG ?= clang
VETH0 ?= veth0
VETH1 ?= veth1
VETH0_IP ?= 10.10.0.1
VETH1_IP ?= 10.10.0.2
SUBNET ?= 24
BRIDGE ?= br-veth
PHYSICAL_IFACE ?= $(shell ip route | grep default | awk '{print $$5}' | head -1)

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

INTERFACE ?= $(VETH0)
BPF_MOUNT ?= /sys/fs/bpf
PROG_NAME ?= xdp_redirect
MAP_NAME ?= xsks_map


# Compilation flags
BPF_CFLAGS = -O2 -g -Wall -target bpf \
             -D__KERNEL__ \
             -I/usr/include \
             -I/usr/include/x86_64-linux-gnu

# Default targets
all: compile load

# Compile eBPF program
compile: redirect_all.o

redirect_all.o: redirect_all.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

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

# Load eBPF program and attach to interface
load-veth: redirect_all.o clean-bpf
	# 1. Load new program
	@echo "Loading eBPF program..."
	sudo bpftool prog load redirect_all.o $(BPF_MOUNT)/$(PROG_NAME)
	
	# 2. Find created map ID
	@echo "Searching for map..."
	@sleep 0.5
	@MAP_ID=$$(sudo bpftool prog show pinned $(BPF_MOUNT)/$(PROG_NAME) 2>/dev/null | \
		grep -o "map_ids [0-9]*" | awk '{print $$2}'); \
	if [ -z "$$MAP_ID" ]; then \
		echo "   ❌ Map not found in program"; \
		echo "   Try manual search:"; \
		sudo bpftool map show | grep xsk; \
		exit 1; \
	fi; \
	echo "   Found map ID: $$MAP_ID"; \
	
	# 3. Pin the map
	@echo "Pinning map..."
	make pin
	
	# 4. Attach program to interface
	@echo "Attaching to interface..."
	sudo bpftool net attach xdp pinned $(BPF_MOUNT)/$(PROG_NAME) dev $(INTERFACE)
	
	# 5. Show info
	@echo ""
	@echo "✅ Program loaded!"
	@echo "   Program: $(BPF_MOUNT)/$(PROG_NAME) (ID: $$MAP_ID)"
	@echo "   Map: $(BPF_MOUNT)/$(MAP_NAME) (ID: $$MAP_ID)"
	@echo "   Interface: $(INTERFACE)"
	@echo ""

# Auto-pin map (if program already loaded)
pin:
	@echo "Searching map for pinning..."
	@MAP_ID=$$(sudo bpftool map show | grep xsks_map | head -1 | awk '{print $$1}' | cut -d: -f1); \
	if [ -z "$$MAP_ID" ]; then \
		echo "❌ Map xsks_map not found"; \
		exit 1; \
	fi; \
	echo "   Found map ID: $$MAP_ID"; \
	echo "   Pinning as $(BPF_MOUNT)/$(MAP_NAME)..."; \
	sudo bpftool map pin id $$MAP_ID $(BPF_MOUNT)/$(MAP_NAME); \
	echo "✅ Map pinned"; \
	sudo ls -la $(BPF_MOUNT)/$(MAP_NAME)

# Unpin map
unpin:
	@echo "=== Unpinning map ==="
	@echo "Checking file: $(BPF_MOUNT)/$(MAP_NAME)"
	@if sudo test -f $(BPF_MOUNT)/$(MAP_NAME); then \
		echo "✅ File found, removing..."; \
		sudo rm -f $(BPF_MOUNT)/$(MAP_NAME); \
		if [ $$? -eq 0 ]; then \
			echo "✅ Map unpinned"; \
		else \
			echo "❌ Error removing"; \
		fi; \
	else \
		echo "⚠️ File not found"; \
		# Check if map exists in kernel \
		MAP_ID=$$(sudo bpftool map show 2>/dev/null | awk '/xsks_map/ {print $$1}' | cut -d: -f1 | head -1); \
		if [ -n "$$MAP_ID" ]; then \
			echo "⚠️ Map exists in kernel (ID: $$MAP_ID), but not pinned"; \
			echo "Use 'make clean-bpf' for complete cleanup"; \
		else \
			echo "✅ Map not found in files or kernel"; \
		fi; \
	fi

# Check status
status-veth:
	@echo "=== Current status ==="
	@echo ""
	@echo "1. Interface $(INTERFACE):"
	@ip link show dev $(INTERFACE) | grep -A1 xdp || echo "   ❌ No XDP program"
	@echo ""
	@echo "2. eBPF programs:"
	@if sudo bpftool prog show | grep -q xdp; then \
		sudo bpftool prog show | grep xdp | while read line; do \
			echo "   ✅ $$line"; \
		done; \
	else \
		echo "   ❌ No XDP programs"; \
	fi
	@echo ""
	@echo "3. XSKMAP maps:"
	@if sudo bpftool map show | grep -q xskmap; then \
		sudo bpftool map show | grep xskmap | while read line; do \
			echo "   ✅ $$line"; \
		done; \
	else \
		echo "   ❌ No XSK maps"; \
	fi
	@echo ""
	@echo "4. Files in $(BPF_MOUNT):"
	@if sudo ls $(BPF_MOUNT)/ 2>/dev/null | grep -q -E "(xdp|xsk)"; then \
		sudo ls -la $(BPF_MOUNT)/ 2>/dev/null | grep -E "(xdp|xsk)"; \
	else \
		echo "   ❌ No files (map not pinned)"; \
	fi
	@echo ""
	@echo "5. Map access check:"
	@if sudo test -f $(BPF_MOUNT)/$(MAP_NAME); then \
		echo "   ✅ Map pinned: $(BPF_MOUNT)/$(MAP_NAME)"; \
		echo "   Size: $$(sudo stat -c%s $(BPF_MOUNT)/$(MAP_NAME) 2>/dev/null) bytes"; \
	else \
		echo "   ❌ Map NOT pinned!"; \
		echo "   Run: make pin"; \
	fi

# Unload program
unload-veth: clean-bpf
	make unpin 
	@echo "✅ Unload complete"

reload-veth:
	make clean
	make compile
	make unload-veth
	make load-veth

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

# Full cleanup
clean:
	rm -f *.o
	make clean-bpf
	@echo "✅ Full cleanup complete"

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

ping-veth:
	ping -I veth1 -c 3 10.10.0.1

fs:
	sudo tree /sys/fs/bpf/

.PHONY: all compile load pin unpin clean-bpf check unload clean help
