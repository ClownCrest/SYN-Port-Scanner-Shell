import argparse
import socket
import subprocess
import re
from scapy.all import *
from netaddr import IPNetwork, IPRange, AddrFormatError

def is_valid_ip(ip):
    """Check if the provided IP is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_local_subnet():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "src" in line:
                match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    local_ip = match.group(1)
                    subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
                    print(f"[*] No target specified. Scanning local subnet: {subnet}")
                    return subnet
        print("[!] Could not detect local network, using fallback method.")
        fallback_ip = socket.gethostbyname(socket.gethostname())
        subnet = fallback_ip.rsplit(".", 1)[0] + ".0/24"
        return subnet
    except Exception as e:
        print(f"[!] Failed to detect local subnet: {e}")
        return "192.168.0.0/24"

def is_host_online(target):
    if target.startswith("127."):
        return True
    try:
        ans, _ = arping(target, timeout=1, verbose=False)
        return len(ans) > 0
    except Exception:
        return False

def syn_scan(target, port):
    ip_packet = IP(dst=target)
    tcp_packet = TCP(dport=port, flags="S", sport=RandShort())
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=False)
    
    if response:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK received
                print(f"[+] {target}:{port} is OPEN")
                return "open"
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK received
                print(f"[-] {target}:{port} is CLOSED")
                return "closed"
        print(f"[?] {target}:{port} is FILTERED")
        return "filtered"
    print(f"[?] {target}:{port} is FILTERED")
    return "filtered"

def scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts):
    print(f"\n[+] Scanning {target} on ports {min(ports)}-{max(ports)}...")
    if not is_host_online(target):
        print(f"[-] {target} is unreachable. Skipping...")
        return
    for port in ports:
        print(f"[*] Scanning {target}:{port}...")
        result = syn_scan(target, port)
        if result == "open":
            open_hosts.append((target, port))
        elif result == "closed":
            closed_hosts.append((target, port))
        elif result == "filtered":
            filtered_hosts.append((target, port))

def parse_arguments():
    parser = argparse.ArgumentParser(description="SYN Scanner Shell for Students")
    parser.add_argument("-t", "--target", help="Target IP, range, or subnet")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., 80,443,1-100)")
    parser.add_argument("--show", help="Filter results: open, closed, filtered")
    args = parser.parse_args()
    
    if not args.target:
        args.target = get_local_subnet()
    
    targets = []
    try:
        if "/" in args.target:
            targets = [str(ip) for ip in IPNetwork(args.target)]
        elif "-" in args.target:
            start_ip, end_ip = args.target.split("-")
            if not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
                raise ValueError("Invalid IP range format.")
            targets = [str(ip) for ip in IPRange(start_ip, end_ip)]
        else:
            if not is_valid_ip(args.target):
                raise ValueError("Invalid IP address.")
            targets = [args.target]
    except (AddrFormatError, ValueError) as e:
        print(f"[!] Error parsing target IP: {e}")
        exit(1)
    
    ports = []
    if args.ports:
        try:
            parts = args.ports.split(",")
            for part in parts:
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    if start < 1 or end > 65535:
                        raise ValueError("Port numbers must be between 1 and 65535.")
                    ports.extend(range(start, end + 1))
                else:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError("Port numbers must be between 1 and 65535.")
                    ports.append(port)
        except ValueError as e:
            print(f"[!] Error parsing ports: {e}")
            exit(1)
    else:
        ports = list(range(1, 65536))
    
    return targets, ports, args.show

if __name__ == "__main__":
    targets, ports, show_filter = parse_arguments()
    open_hosts, closed_hosts, filtered_hosts = [], [], []
    
    print("\n[+] Starting scan...")
    for target in targets:
        scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts)
    
    print("\n[+] Scan Complete")
