#!/bin/bash

set -e

# make sure we haven't already run this script
if ip netns exec my-ns true > /dev/null 2>&1; then
  echo "ERROR: namespace already exists" >&2
  exit 1
fi

ip netns add my-ns

ip link add my-veth type veth peer name my-ceth netns my-ns

ip addr add 10.1.2.1/24 dev my-veth
ip link set my-veth up

ip -n my-ns addr add 10.1.2.50/24 dev my-ceth
ip -n my-ns link set my-ceth up
ip -n my-ns route add default via 10.1.2.1

iptables -t nat -A POSTROUTING -s 10.1.2.0/24 -j LOG
iptables -t nat -A POSTROUTING -s 10.1.2.0/24 ! -o my-veth -j MASQUERADE
