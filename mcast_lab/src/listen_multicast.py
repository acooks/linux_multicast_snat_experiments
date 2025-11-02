#!/usr/bin/env python3
import socket
import struct
import sys

def listen_multicast(listen_ip, mcast_group, mcast_port):
    """
    A simple multicast listener that joins a group on a specific interface.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the multicast group address on all interfaces.
    # The IP_ADD_MEMBERSHIP option will control which interface actually
    # receives the traffic.
    sock.bind(("", mcast_port))

    # Tell the kernel to join the multicast group on the specific interface.
    mreq = struct.pack("4s4s", socket.inet_aton(mcast_group), socket.inet_aton(listen_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"Listening for multicast on {listen_ip} for group {mcast_group}:{mcast_port}...", file=sys.stderr)

    # Wait for one packet
    data, addr = sock.recvfrom(1024)
    print(f"Received packet from {addr}: {data.decode().strip()}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <listen_ip> <mcast_group> <mcast_port>", file=sys.stderr)
        sys.exit(1)
    
    listen_ip = sys.argv[1]
    mcast_group = sys.argv[2]
    mcast_port = int(sys.argv[3])
    
    listen_multicast(listen_ip, mcast_group, mcast_port)
