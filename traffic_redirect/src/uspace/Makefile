# Compilation configuration
CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra
LDFLAGS ?=

# Paths and libraries
XDP_LIBS = -lxdp -lbpf -lpthread
XDP_INCLUDES = -I/usr/include/xdp -I/usr/include/bpf
IFNAME ?= lo
QUEUE_ID ?= 0

# File names
TARGET = xdp_app
SRC = main.cpp
OBJ = $(SRC:.cpp=.o)

# Default targets
all: $(TARGET)

# Main build
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(XDP_LIBS) $(LDFLAGS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) $(XDP_INCLUDES) -c $< -o $@

# Run program
run: $(TARGET)
	@echo "=== Running AF_XDP program ==="
	@echo "Interface: $(IFNAME)"
	@echo "Queue: $(QUEUE_ID)"
	@echo ""
	sudo ./$(TARGET)

# Clean
clean:
	rm -f $(OBJ) $(TARGET)

# Clean all objects (including eBPF)
clean-all: clean
	@echo "Cleaning eBPF objects..."
	-sudo ip link set dev $(IFNAME) xdp off 2>/dev/null
	-sudo rm -f /sys/fs/bpf/xdp_redirect /sys/fs/bpf/xsks_map 2>/dev/null

# Check system status
check:
	@echo "=== System status ==="
	@echo "1. XDP on interface $(IFNAME):"
	@ip link show dev $(IFNAME) | grep xdp || echo "   ❌ No XDP"
	@echo ""
	@echo "2. Maps in /sys/fs/bpf/:"
	@sudo ls -la /sys/fs/bpf/ 2>/dev/null | grep -E "(xdp|xsk)" || echo "   ❌ No files"
	@echo ""
	@echo "3. eBPF programs:"
	@sudo bpftool prog show 2>/dev/null | grep xdp || echo "   ❌ No programs"
	@echo ""
	@echo "4. XSK maps:"
	@sudo bpftool map show 2>/dev/null | grep xsk || echo "   ❌ No maps"

# Help
help:
	@echo "=== AF_XDP Userspace Makefile ==="
	@echo ""
	@echo "Main commands:"
	@echo "  make all           - compile program"
	@echo "  make run           - run program"
	@echo "  make check        	- check system status
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - remove compiled files"
	@echo "  make clean-all     - full cleanup (including eBPF)"
	@echo ""
	@echo "Help:"
	@echo "  make help          - this help"
	@echo ""

.PHONY: all run debug test quick clean clean-all status monitor check-deps install-deps help