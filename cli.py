#!/usr/bin/env python3
import argparse
from scapy.all import sniff, TCP, Raw
from datetime import datetime
from scapy.layers.http import HTTPRequest
import re
import json
import os
import configparser
import asyncio
import threading
import subprocess

try:
    from mitmproxy import http
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

CONFIG_FILE = os.path.expanduser("~/.xrayauth_config.ini")

def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        return config['XRayAuth']
    else:
        config['XRayAuth'] = {
            'interface': 'eth0',
            'log': os.path.expanduser('~/xrayauth_logs.json')
        }
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        return config['XRayAuth']

session_db = {}

token_patterns = [
    re.compile(rb"Cookie:.*?session=.*?\r\n", re.IGNORECASE),
    re.compile(rb"Authorization: Bearer (.*?)\r\n", re.IGNORECASE)
]

def extract_token_info(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        src_ip = packet[1].src
        user_agent = re.search(rb"User-Agent: (.*?)\r\n", payload)
        for pattern in token_patterns:
            match = pattern.search(payload)
            if match:
                token = match.group(0).decode(errors='ignore')
                user_agent_str = user_agent.group(1).decode(errors='ignore') if user_agent else "Unknown"
                return src_ip, token.strip(), user_agent_str
    return None, None, None

def log_event(entry, log_file):
    entry['timestamp'] = datetime.now().isoformat()
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry) + "\n")

def detect_anomaly(src_ip, token, user_agent, log_file):
    if token in session_db:
        existing = session_db[token]
        if existing['ip'] != src_ip:
            print("\n[!] Possible Session Hijack Detected!")
            print(f"[-] Token reused from new IP: {src_ip}")
            print(f"[-] Old IP: {existing['ip']}, Old UA: {existing['ua']}\n")
            log_event({
                "type": "anomaly",
                "token": token,
                "new_ip": src_ip,
                "old_ip": existing['ip'],
                "old_ua": existing['ua'],
                "new_ua": user_agent
            }, log_file)
    else:
        session_db[token] = {"ip": src_ip, "ua": user_agent}
        log_event({"type": "new_session", "ip": src_ip, "ua": user_agent, "token": token}, log_file)

def packet_handler(packet, log_file):
    if packet.haslayer(HTTPRequest):
        method = packet[HTTPRequest].Method.decode()
        host = packet[HTTPRequest].Host.decode()
        path = packet[HTTPRequest].Path.decode()
        log_line = f"[{datetime.now()}] {method} http://{host}{path}\n"
        print(log_line.strip())
        with open(log_file, "a") as logfile:
            logfile.write(json.dumps({
                "type": "http_request",
                "timestamp": datetime.now().isoformat(),
                "method": method,
                "host": host,
                "path": path
            }) + "\n")

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        src_ip, token, user_agent = extract_token_info(packet)
        if token:
            detect_anomaly(src_ip, token, user_agent, log_file)

class InterceptAddon:
    def __init__(self, log_file):
        self.log_file = log_file

    def request(self, flow):
        src_ip = flow.client_conn.peername[0]
        token = None
        user_agent = flow.request.headers.get("User-Agent", "Unknown")
        if "Cookie" in flow.request.headers:
            cookie = flow.request.headers["Cookie"]
            if "session=" in cookie:
                token = f"Cookie: {cookie}"
        if "Authorization" in flow.request.headers:
            token = f"Authorization: {flow.request.headers['Authorization']}"
        if token:
            detect_anomaly(src_ip, token, user_agent, self.log_file)

def free_port(port=8080):
    try:
        result = subprocess.check_output(["lsof", "-t", f"-i:{port}"])
        pids = result.decode().strip().split("\n")
        for pid in pids:
            print(f"[!] Killing process on port {port}: PID {pid}")
            subprocess.run(["kill", "-9", pid])
    except subprocess.CalledProcessError:
        pass

def run_mitmproxy(log_file):
    if not MITMPROXY_AVAILABLE:
        print("[-] HTTPS support requires mitmproxy. Install it with: pip install mitmproxy")
        return

    free_port(8080)

    class InterceptRunner:
        def __init__(self, log_file):
            self.log_file = log_file

        async def run(self):
            options = Options(listen_host="0.0.0.0", listen_port=8080)
            master = DumpMaster(options, with_termlog=False, with_dumper=False)
            master.addons.add(InterceptAddon(self.log_file))
            try:
                await master.run()
            except asyncio.CancelledError:
                print("[!] HTTPS monitor stopped.")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runner = InterceptRunner(log_file)
    try:
        loop.run_until_complete(runner.run())
    except KeyboardInterrupt:
        print("\n[!] Stopping HTTPS monitor...")
    finally:
        loop.stop()
        loop.close()

def print_banner():
    print("=" * 50)
    print("🛡️  XRayAuth - Session Hijack Detection Tool")
    print("📦  Version: 1.0.0")
    print("👤  Author: Akki")
    print("=" * 50)

def main():
    print_banner()
    config = load_config()

    parser = argparse.ArgumentParser(description="XRayAuth - Session Hijack Detection Tool")
    parser.add_argument("-i", "--interface", default=config['interface'], help="Network interface to sniff on (e.g., eth0)")
    parser.add_argument("-l", "--log", default=config['log'], help="Log file path")
    parser.add_argument("--https", action='store_true', help="Enable HTTPS monitoring via mitmproxy")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        open(args.log, 'w').close()

    print(f"[*] Monitoring interface {args.interface} for HTTP traffic...")

    stop_event = threading.Event()

    sniff_thread = threading.Thread(target=lambda: sniff(
        iface=args.interface,
        filter="tcp port 80",
        prn=lambda pkt: packet_handler(pkt, args.log),
        store=0,
        stop_filter=lambda pkt: stop_event.is_set()
    ))
    sniff_thread.start()

    try:
        if args.https:
            print("[*] HTTPS monitoring enabled on port 8080 using mitmproxy")
            run_mitmproxy(args.log)
        else:
            sniff_thread.join()
    except KeyboardInterrupt:
        print("\n[!] Stopping packet capture...")
        stop_event.set()
        sniff_thread.join()
        print("[*] Capture stopped cleanly.")

if __name__ == "__main__":
    main()