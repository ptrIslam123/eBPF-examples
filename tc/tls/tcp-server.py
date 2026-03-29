#!/usr/bin/env python3
"""
TCP Echo Server with command-line arguments
Usage: python3 tcp_server.py [options]
"""

import socket
import argparse
import sys
import threading

def handle_client(conn, addr):
    try:
        # Receive data
        data = conn.recv(4096)
        if not data:
            return
            
        print(f"Received {len(data)} bytes from {addr}: {data[:50]}")
            
        # Echo back
        conn.send(data)
            
    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        conn.close()
        print(f"Client disconnected: {addr}")

parser = argparse.ArgumentParser(description='TCP Echo Server')
parser.add_argument('--bind-ip', type=str, default='0.0.0.0',
                    help='IP address to bind to (default: 0.0.0.0)')
parser.add_argument('--port', type=int, default=0,
                    help='Port to listen on (default: 0)')

args = parser.parse_args()
    
# Create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind to interface
try:
    server_socket.bind((args.bind_ip, args.port))
except Exception as e:
    print(f"Error binding to {args.bind_ip}:{args.port}: {e}")
    sys.exit(1)

# Listen for connections
server_socket.listen(5)
print(f"✓ TCP Echo Server listening on {args.bind_ip}:{args.port}")

print("Server running. Press Ctrl+C to stop.")
try:
    while True:
        conn, addr = server_socket.accept()
        print(f"New connection from {addr}")
        
        # Handle client in separate thread
        client_thread = threading.Thread(
            target=handle_client,
            args=(conn, addr)
        )
        client_thread.daemon = True
        client_thread.start()
        
except KeyboardInterrupt:
    print("\nShutting down server...")
finally:
    server_socket.close()
    print("Server stopped")