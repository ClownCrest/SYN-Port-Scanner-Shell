import argparse
import socket
import subprocess
import re
from scapy.all import IP, sr1, send, RandShort, arping
from netaddr import IPNetwork, IPRange  # Ensure netaddr is installed

# Function to detect local subnet (if no target is provided)
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
        return "192.168.0.0/24"  # Default if detection fails

# Function to check if a host is online using ARP
def is_host_online(target):
    """
    Uses ARP to check if a target is online.
    Loopback addresses (127.x.x.x) are always considered reachable.
    """
    if target.startswith("127."):
        return True

    ans, _ = arping(target, timeout=1, verbose=False)
    return len(ans) > 0

# Function to perform a SYN scan on a given port
def syn_scan(target, port):
    """
    Constructs a SYN packet using Scapy, sends it to the target,
    and analyzes the response:
        - If a SYN-ACK is received, the port is OPEN.
        - If an RST is received, the port is CLOSED.
        - If no response is received, the port is FILTERED.
    Returns the status as a string: "open", "closed", or "filtered".
    """
    ip_packet = IP(dst=target)
    tcp_packet = TCP(dport=port, flags="S", sport=RandShort())
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=False)

    if response is None:
        return "filtered"
    elif response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        # If SYN-ACK (flags 0x12) is received, the port is open.
        if tcp_layer.flags == 0x12:
            # Send an RST packet to gracefully close the connection.
            rst_pkt = IP(dst=target) / TCP(dport=port, flags="R", sport=tcp_packet.sport, seq=tcp_layer.ack)
            send(rst_pkt, verbose=False)
            return "open"
        # If RST (flags 0x14) is received, the port is closed.
        elif tcp_layer.flags == 0x14:
            return "closed"
    return "filtered"

# Function to scan a given target on specified ports
def scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts):
    """
    - Print the scanning message with the target IP and port range.
    - Use `is_host_online(target)` to check if the host is reachable.
    - If the host is online, iterate through the ports and:
        - Call `syn_scan(target, port)` for each port.
        - Categorize the result into open, closed, or filtered lists.
    """
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

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="SYN Scanner Shell for Students")
    parser.add_argument("-t", "--target", help="Target IP, range, or subnet")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., 80,443,1-100)")
    parser.add_argument("--show", help="Filter results: open, closed, filtered")

    args = parser.parse_args()

    if not args.target:
        args.target = get_local_subnet()

    # Implement target parsing (supporting single IP, range, subnet)
    targets = []
    if "/" in args.target:
        # Subnet notation, e.g., 192.168.1.0/24
        try:
            targets = [str(ip) for ip in IPNetwork(args.target)]
        except Exception as e:
            print(f"[!] Error parsing subnet: {e}")
            targets = [args.target]
    elif "-" in args.target:
        # IP range, e.g., 192.168.1.1-192.168.1.100
        try:
            start_ip, end_ip = args.target.split("-")
            targets = [str(ip) for ip in IPRange(start_ip, end_ip)]
        except Exception as e:
            print(f"[!] Error parsing IP range: {e}")
            targets = [args.target]
    else:
        # Single IP address
        targets = [args.target]

    # Implement port parsing (supporting single ports, ranges, lists)
    ports = []
    if args.ports:
        try:
            parts = args.ports.split(",")
            for part in parts:
                if "-" in part:
                    start, end = part.split("-")
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        except Exception as e:
            print(f"[!] Error parsing ports: {e}")
            ports = [80, 443]  # fallback default
    else:
        ports = [80, 443]  # Default ports if not provided

    return targets, ports

if __name__ == "__main__":
    """
    TODO:
    - Call `parse_arguments()` to get the list of targets and ports.
    - Create empty lists for open, closed, and filtered ports.
    - Loop through each target and call `scan_target()`.
    - Print a final summary of open, closed, and filtered ports.
    """
    targets, ports = parse_arguments()

    open_hosts = []
    closed_hosts = []
    filtered_hosts = []

    print("\n[+] Starting scan...")
    for target in targets:
        scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts)

    print("\n[+] Scan Summary:")
    if show_filter:
        show_filter = show_filter.lower()
        if show_filter == "open":
            print(f"  Open Ports: {open_hosts}")
        elif show_filter == "closed":
            print(f"  Closed Ports: {closed_hosts}")
        elif show_filter == "filtered":
            print(f"  Filtered Ports: {filtered_hosts}")
        else:
            print("  Invalid filter option provided. Showing all results:")
            print(f"  Open Ports: {open_hosts}")
            print(f"  Closed Ports: {closed_hosts}")
            print(f"  Filtered Ports: {filtered_hosts}")
    else:
        print(f"  Open Ports: {open_hosts}")
        print(f"  Closed Ports: {closed_hosts}")
        print(f"  Filtered Ports: {filtered_hosts}")
