import socket
import struct
import time
import csv
import json
import os
from collections import Counter
from threading import Thread


def get_mac(bytes_addr):
    if bytes_addr:
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    return 'UNKNOWN'


def get_ip(addr):
    return '.'.join(map(str, addr))


def ethernet_frame(data):
    try:
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]
    except struct.error:
        return None, None, None, data


def ipv4_packet(data):
    if len(data) < 20:
        return None, None, None, None, None, data
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    if len(data) < header_length:
        return None, None, None, None, None, data
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return header_length, ttl, proto, get_ip(src), get_ip(target), data[header_length:]


def log_packet(timestamp, src_ip, dest_ip, proto_name):
    with open('packet_log.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, src_ip, dest_ip, proto_name])


PROTOCOLS = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
alert_counter = Counter()

def monitor_alerts(log_file):
    print("Monitoring live alerts...")
    try:
        with open(log_file, 'r') as file:
            file.seek(0, os.SEEK_END)
            while True:
                line = file.readline()
                if line:
                    try:
                        alert = json.loads(line)
                        if 'alert' in alert:
                            alert_msg = alert['alert']['signature']
                            alert_counter[alert_msg] += 1
                            print(f"[ALERT] {alert_msg} (Count: {alert_counter[alert_msg]})")
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        print(f"Log file '{log_file}' not found!")


with open('packet_log.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol"])

log_file_path = '/var/log/suricata/eve.json'
Thread(target=monitor_alerts, args=(log_file_path,), daemon=True).start()

try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except PermissionError:
    print("Permission denied. Run the script as root or with sudo.")
    exit(1)

print("Network Intrusion Detection System (NIDS) started...\nListening for packets and live alerts...")

try:
    while True:
        raw_data, addr = sock.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        if eth_proto == 8 and data:
            result = ipv4_packet(data)
            if result[0] is not None:
                header_length, ttl, proto, src_ip, dest_ip, data = result
                proto_name = PROTOCOLS.get(proto, f"Unknown({proto})")
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                log_packet(timestamp, src_ip, dest_ip, proto_name)
                print(f"[{timestamp}] IPv4 Packet: {src_ip} -> {dest_ip}, Protocol: {proto_name}")

except KeyboardInterrupt:
    print("\nPacket sniffing stopped.")
except OSError as e:
    print(f"Socket error: {e}")
    exit(1)
