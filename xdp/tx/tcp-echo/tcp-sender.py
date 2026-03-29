#!/usr/bin/env python3

import socket
import argparse
import sys

parser = argparse.ArgumentParser(description='TCP Client')
parser.add_argument('--src-ip', type=str, help='source ip address')
parser.add_argument('--src-port', type=int, help='source port')
parser.add_argument('--dst-ip', type=str, required=True, help='destination ip address')
parser.add_argument('--dst-port', type=int, required=True, help='destination port')
parser.add_argument('--iface', type=str, help='interface name (for binding)')
parser.add_argument('--message', type=str, default='hello world', help='transfer message data')

args = parser.parse_args()

# Create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.settimeout(args.timeout)

# Bind to source if specified
if args.src_ip:
    src_addr = (args.src_ip, args.src_port or 0)
    try:
        sock.bind(src_addr)
        print(f"Bound to {args.src_ip}:{args.src_port or 'random'}")
    except Exception as e:
        print(f"Error binding to {args.src_ip}:{args.src_port}: {e}")
        sys.exit(1)

# Bind to interface if specified (Linux only)
if args.iface:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.iface.encode())
        print(f"Bound to interface: {args.iface}")
    except Exception as e:
        print(f"Error binding to interface {args.iface}: {e}")

try:
    # Connect
    print(f"Connecting to {args.dst_ip}:{args.dst_port}...")
    
    sock.connect((args.dst_ip, args.dst_port))
    print(f"✓ Connected to {args.dst_ip}:{args.dst_port}")
except Exception as e:
    print(f"connect error: {e}")
    exit(-1)

# Send message
sent = sock.send(args.message.encode())
print(f"Sent: {sent}")

# Receive response
try:
    response = sock.recv(4096)
    if response:
        print(f"Response: {response.decode()}")
    else:
        print("Server closed connection")
except socket.timeout:
    print("Timeout waiting for response")
    exit(-1)
