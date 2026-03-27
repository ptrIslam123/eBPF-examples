
# Working veth pair with external connectivity
# Based on the proven bash script

NS := test_ns
VETH1 := veth1
VETH2 := veth2
VETH1_IP := 10.10.0.1
VETH2_IP := 10.10.0.2
NETMASK := 24
NETWORK := 10.10.0.0/24

.PHONY: setup cleanup status test shell

setup:
	@# Check if namespace already exists
	@if ip netns exec $(NS) true 2>/dev/null; then \
		echo "ERROR: namespace $(NS) already exists" >&2; \
		exit 1; \
	fi
	@# Create namespace
	ip netns add $(NS)
	@# Create veth pair with one end in namespace
	ip link add $(VETH1) type veth peer name $(VETH2) netns $(NS)
	@# Configure host side
	ip addr add $(VETH1_IP)/$(NETMASK) dev $(VETH1)
	ip link set $(VETH1) up
	@# Configure namespace side
	ip -n $(NS) addr add $(VETH2_IP)/$(NETMASK) dev $(VETH2)
	ip -n $(NS) link set $(VETH2) up
	ip -n $(NS) route add default via $(VETH1_IP)
	@# Enable IP forwarding
	echo 1 > /proc/sys/net/ipv4/ip_forward
	@# Add NAT with exclusion for veth interface (critical!)
	iptables -t nat -A POSTROUTING -s $(NETWORK) -j LOG
	iptables -t nat -A POSTROUTING -s $(NETWORK) ! -o $(VETH1) -j MASQUERADE
	@echo ""
	@echo "✓ veth pair setup complete"
	@echo "  Host: $(VETH1) = $(VETH1_IP)"
	@echo "  Namespace: $(NS) = $(VETH2_IP) (via $(VETH2))"
	@echo ""
	@echo "Test: sudo ip netns exec $(NS) ping 8.8.8.8"

cleanup:
	@# Delete namespace (removes veth automatically)
	-ip netns delete $(NS) 2>/dev/null
	@# Delete host veth if it still exists
	-ip link delete $(VETH2) 2>/dev/null
	@# Remove iptables rules
	-iptables -t nat -D POSTROUTING -s $(NETWORK) -j LOG 2>/dev/null
	-iptables -t nat -D POSTROUTING -s $(NETWORK) ! -o $(VETH1) -j MASQUERADE 2>/dev/null
	@echo "✓ Cleanup complete"

status:
	@echo "=== Namespace ==="
	@ip netns list | grep $(NS) || echo "Namespace not found"
	@echo ""
	@echo "=== Host veth ==="
	@ip addr show $(VETH1) 2>/dev/null || echo "veth not found"
	@echo ""
	@echo "=== Namespace interfaces ==="
	@ip -n $(NS) addr show 2>/dev/null || echo "Cannot access namespace"
	@echo ""
	@echo "=== Routes in namespace ==="
	@ip -n $(NS) route show 2>/dev/null || echo "No routes"
	@echo ""
	@echo "=== IP Forwarding ==="
	@cat /proc/sys/net/ipv4/ip_forward

test:
	@echo "Testing connectivity..."
	@echo -n "  Namespace -> host: "
	@ip netns exec $(NS) ping -c 1 -W 1 $(VETH2_IP) >/dev/null 2>&1 && echo "✓ OK" || echo "✗ FAILED"
	@echo -n "  Namespace -> 8.8.8.8: "
	@ip netns exec $(NS) ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo "✓ OK" || echo "✗ FAILED"
	@echo -n "  Namespace -> google.com: "
	@ip netns exec $(NS) ping -c 1 -W 2 google.com >/dev/null 2>&1 && echo "✓ OK" || echo "✗ FAILED"

shell:
	@echo "Entering namespace $(NS)..."
	@echo "Try: ping 8.8.8.8"
	@ip netns exec $(NS) bash --rcfile <(echo "PS1='$(NS)> '")
