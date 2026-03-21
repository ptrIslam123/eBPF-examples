import socket
import argparse
import sys

parser = argparse.ArgumentParser(description='Send UDP hello world message')
parser.add_argument('--iface', help='Network interface name (optional, root required)')
parser.add_argument('--src_ip', help='Source IP address')
parser.add_argument('--src_port', type=int, help='Source port')
parser.add_argument('--dst_ip', help='Destination IP address')
parser.add_argument('--dst_port', type=int, help='Destination port')
parser.add_argument('--message', default='hello world', help='Message to send')

args = parser.parse_args()

try:
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind to interface if requested
    if args.iface:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            args.iface.encode('utf-8'))
            print(f"Bound to interface: {args.iface}")
        except Exception as e:
            print(f"Warning: Could not bind to interface {args.iface}: {e}")
            sys.exit(1)
    
    # Bind to source IP and port
    sock.bind((args.src_ip, args.src_port))
    
    # Send message
    message_bytes = args.message.encode('utf-8')
    bytes_sent = sock.sendto(message_bytes, (args.dst_ip, args.dst_port))
 
    print(f"  From: {args.src_ip}:{args.src_port}")
    if args.iface:
        print(f"  Interface: {args.iface}")
    print(f"  To: {args.dst_ip}:{args.dst_port}")
    print(f"  Message: '{args.message}'")
    print(f"  Bytes sent: {bytes_sent}")
    
    
    data, addr = sock.recvfrom(1024)
    print(f"Receivee messgae={data} from={addr}")
    
    sock.close()
    
except socket.error as e:
    print(f"Socket error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    sys.exit(1)