# SYN Port Scanner Shell

## Overview
This Python script is a SYN scanner designed for network security students. It allows users to scan a target IP, IP range, or subnet for open, closed, and filtered ports. The scanner supports I/O multiplexing and leverages ARP requests and SYN packets to determine port states.

## Features
- Scans single IPs, IP ranges, or subnets.
- Uses ARP to check host availability.
- Performs SYN scans to determine open, closed, or filtered ports.
- Supports local network auto-detection.
- Provides filtering options to display specific scan results.

## Prerequisites
Ensure you have the following dependencies installed before running the script:
- Python 3.x
- `scapy`
- `netaddr`

You can install the required packages using:
```sh
pip install scapy netaddr
```

## Usage
Run the script with the following options:
```sh
python syn_scanner.py [-t TARGET] [-p PORTS] [--show FILTER]
```

### Arguments:
- `-t, --target` : Specify the target IP, range, or subnet (e.g., `192.168.1.1`, `192.168.1.0/24`, `192.168.1.10-192.168.1.50`).
- `-p, --ports` : Specify port(s) to scan (e.g., `80`, `443`, `1-100`). Defaults to all ports (1-65535) if not specified.
- `--show` : Filter results by `open`, `closed`, or `filtered` ports.

### Example Commands:
Scan a single IP on ports 80 and 443:
```sh
python syn_scanner.py -t 192.168.1.1 -p 80,443
```

Scan an entire subnet:
```sh
python syn_scanner.py -t 192.168.1.0/24 -p 1-100
```

Show only open ports:
```sh
python syn_scanner.py -t 192.168.1.1 -p 1-100 --show open
```

## How It Works
1. If no target is specified, the script attempts to detect the local subnet.
2. Uses ARP to check if the target is online.
3. Performs a SYN scan (or connect scan for localhost) to determine the port status.
4. Displays results in an organized format.

## Limitations
- Requires root/admin privileges to send raw packets.
- May not work on networks with strict firewall rules.
- ARP detection is limited to local networks.

## Disclaimer
This tool is intended for educational and authorized security testing purposes only. Unauthorized scanning of networks may be illegal in some jurisdictions.

