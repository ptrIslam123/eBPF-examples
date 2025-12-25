# Configuration
CLANG ?= clang
INTERFACE ?= lo
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

# Load eBPF program and attach to interface
load: redirect_all.o clean-bpf
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

# Check status
check:
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
unload: clean-bpf
	make unpin 
	@echo "✅ Unload complete"

# Full cleanup
clean:
	rm -f *.o
	make clean-bpf
	@echo "✅ Full cleanup complete"

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Help
help:
	@echo "Available commands:"
	@echo ""
	@echo "BASIC:"
	@echo "  make all                 - compile and load (recommended)"
	@echo "  make compile             - compile eBPF program only"
	@echo "  make load                - load with automatic map pinning"
	@echo ""
	@echo "MAP MANAGEMENT:"
	@echo "  make pin                 - pin map (if program already loaded)"
	@echo "  make unpin               - unpin map"
	@echo ""
	@echo "CHECK:"
	@echo "  make check               - check current status"
	@echo ""
	@echo "CLEANUP:"
	@echo "  make unload              - unload program (keeps .o files)"
	@echo "  make clean               - full cleanup (including .o files)"
	@echo ""
	@echo "HELP:"
	@echo "  make help                - this help"

.PHONY: all compile load pin unpin clean-bpf check unload clean help
