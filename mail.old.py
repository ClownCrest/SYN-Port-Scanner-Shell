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
    ans, _ = arping(target, timeout=1, verbose=False)
    return len(ans) > 0

def syn_scan(target, port):
    if target == "127.0.0.1":
        # Use connect scan for localhost
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((target, port))
            sock.close()
            return "open"
        except (socket.timeout, ConnectionRefusedError):
            return "closed"
    
    # Regular SYN scan for external targets
    ip_packet = IP(dst=target)
    tcp_packet = TCP(dport=port, flags="S", sport=RandShort())
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=False)

    if response is None:
        return "filtered"
    elif response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            rst_pkt = IP(dst=target) / TCP(dport=port, flags="R", sport=tcp_packet.sport, seq=tcp_layer.ack)
            send(rst_pkt, verbose=False)
            return "open"
        elif tcp_layer.flags == 0x14:
            return "closed"
    
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
            print(f"[+] {target}:{port} is open.")
        elif result == "closed":
            closed_hosts.append((target, port))
            print(f"[-] {target}:{port} is closed.")
        elif result == "filtered":
            filtered_hosts.append((target, port))
            print(f"[?] {target}:{port} is filtered.")

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
                    start, end = part.split("-")
                    if not start.isdigit() or not end.isdigit():
                        raise ValueError("Ports must be numeric.")
                    start, end = int(start), int(end)
                    if start < 1 or end > 65535:
                        raise ValueError("Port numbers must be between 1 and 65535.")
                    ports.extend(range(start, end + 1))
                else:
                    if not part.isdigit():
                        raise ValueError("Ports must be numeric.")
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
    open_hosts = []
    closed_hosts = []
    filtered_hosts = []
    print("\n[+] Starting scan...")
    for target in targets:
        scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts)
    
    # Sort results by IP and port
    open_hosts_sorted = sorted(open_hosts, key=lambda x: (x[0], x[1]))
    closed_hosts_sorted = sorted(closed_hosts, key=lambda x: (x[0], x[1]))
    filtered_hosts_sorted = sorted(filtered_hosts, key=lambda x: (x[0], x[1]))

    # Format results as "IP:port" strings
    def format_results(hosts):
        return [f"{ip}:{port}" for ip, port in hosts]

    open_formatted = format_results(open_hosts_sorted)
    closed_formatted = format_results(closed_hosts_sorted)
    filtered_formatted = format_results(filtered_hosts_sorted)

    print("\n[+] Final Scan Summary:\n")
    def print_section(title, entries):
        print(f"  {title}:")
        for entry in entries:
            print(f"  - {entry}")
        print()

    if show_filter:
        show_filter = show_filter.lower()
        if show_filter == "open":
            print_section("Open Ports", open_formatted)
        elif show_filter == "closed":
            print_section("Closed Ports", closed_formatted)
        elif show_filter == "filtered":
            print_section("Filtered Ports", filtered_formatted)
        else:
            print("  Invalid filter option. Showing all results:")
            print_section("Open Ports", open_formatted)
            print_section("Closed Ports", closed_formatted)
            print_section("Filtered Ports", filtered_formatted)
    else:
        print_section("Open Ports", open_formatted)
        print_section("Closed Ports", closed_formatted)
        print_section("Filtered Ports", filtered_formatted)
