import socket
import struct
import binascii
import time
import csv


def ethernet_frame(data):
    try:
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]
    except struct.error:
        return None, None, None, data


def get_mac(bytes_addr):
    if bytes_addr:
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    return 'UNKNOWN'


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ip(src), get_ip(target), data[header_length:]


def ipv6_packet(data):
    version_traffic_flow = struct.unpack('! I', data[:4])[0]
    version = version_traffic_flow >> 28
    payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
    src = get_ipv6(data[8:24])
    target = get_ipv6(data[24:40])
    return version, payload_length, next_header, hop_limit, src, target, data[40:]


def get_ip(addr):
    return '.'.join(map(str, addr))


def get_ipv6(addr):
    return ':'.join('{:x}'.format(int.from_bytes(addr[i:i + 2], 'big')) for i in range(0, 16, 2))


def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Protocol mapping
PROTOCOLS = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}


# Logging setup
log_file = 'packet_log.csv'
with open(log_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"])


try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except PermissionError:
    print("Permission denied. Run the script as root or with sudo.")
    exit(1)

print("Packet sniffer started. Listening for incoming packets...")

try:
    while True:
        raw_data, addr = sock.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        if dest_mac and src_mac and eth_proto is not None:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[{timestamp}] Ethernet Frame:")
            print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

            if eth_proto == 8:  # IPv4
                version, header_length, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
                proto_name = PROTOCOLS.get(proto, f"Unknown({proto})")
                print(f"IPv4 Packet: Version: {version}, Source: {src_ip}, Destination: {dest_ip}, Protocol: {proto_name}")

                if proto == 6:  # TCP
                    src_port, dest_port, sequence, acknowledgment, offset, data = tcp_segment(data)
                    print(f"TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}")

                elif proto == 17:  # UDP
                    src_port, dest_port, size, data = udp_segment(data)
                    print(f"UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")
                
                # Log packet info
                with open(log_file, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([timestamp, src_ip, dest_ip, proto_name, src_port if proto in (6, 17) else '', dest_port if proto in (6, 17) else ''])

            elif eth_proto == 56710:  # IPv6
                version, payload_length, next_header, hop_limit, src_ip, dest_ip, data = ipv6_packet(data)
                print(f"IPv6 Packet: Version: {version}, Source: {src_ip}, Destination: {dest_ip}, Next Header: {next_header}, Hop Limit: {hop_limit}")

except KeyboardInterrupt:
    print("\nPacket sniffing stopped.")
except OSError as e:
    print(f"Socket error: {e}")
    exit(1)
