#!/bin/bash
NET_NS0=$1
NET_NS1=$2
VETH0=$3
VETH1=$4
UPROG=$5
KPROG=$6
DUMMY="dummy"

echo "$1"

sudo ip netns exec $NET_NS0 ip link set dev $VETH0 xdp obj ./$KPROG.o sec xdp
sudo ip netns exec $NET_NS1 ip link set dev $VETH1 xdp obj ./$DUMMY.o sec xdp

MAP_ID=$(bpftool map show | grep xsks_map | head -1 | awk '{print $1}' | cut -d: -f1)
if [ -n "$MAP_ID" ]; then
    echo "Found map ID: $MAP_ID"
    bpftool map pin id $MAP_ID /sys/fs/bpf/xsks_map
    ls -la /sys/fs/bpf/xsks_map
else
    echo "❌ Clould not find map!"
    exit 1
fi

echo "=== Start AF_XDP app $UPROG ==="
./$UPROG --iface veth0 --queue 0 --key 1234567812345678