# project
 Personal Firewall using Python
Day 1 – Monitoring Firewall

Goal:

Monitor all network traffic and log it.

Identify direction (incoming/outgoing) and match packets against rules.

Python Script: firewall_day1.py
#!/usr/bin/env python3
"""
Personal Firewall - Day 1 (Monitoring Only)
-------------------------------------------
- Sniffs packets with Scapy
- Logs incoming/outgoing packets
- Basic IP/Port/Protocol rule matching (non-enforcing)
"""

from scapy.all import sniff, IP, TCP, UDP
import json
import logging
import socket

# -------------------------
# Direction Detection
# -------------------------
def get_local_ips():
    local_ips = []
    hostname = socket.gethostname()
    try:
        local_ips.append(socket.gethostbyname(hostname))
    except socket.gaierror:
        pass
    local_ips.extend(["127.0.0.1", "0.0.0.0"])
    return local_ips

LOCAL_IPS = get_local_ips()

def get_direction(packet):
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        if src in LOCAL_IPS:
            return "outgoing"
        elif dst in LOCAL_IPS:
            return "incoming"
    return "unknown"

# -------------------------
# Rule Matching
# -------------------------
def load_rules(path="rules.json"):
    with open(path) as f:
        return json.load(f)

def match_rules(packet, rules):
    try:
        if IP in packet and packet[IP].src in rules.get("block_ips", []):
            return False
        if TCP in packet and int(packet[TCP].sport) in rules.get("block_ports", []):
            return False
        if UDP in packet and int(packet[UDP].sport) in rules.get("block_ports", []):
            return False
    except Exception as e:
        logging.error(f"Rule matching error: {e}")
    return True

# -------------------------
# Packet Callback
# -------------------------
def packet_callback(packet):
    direction = get_direction(packet)
    action = "ALLOWED" if match_rules(packet, rules) else "BLOCKED"
    msg = f"[{action}] {direction} {packet.summary()}"
    print(msg)
    logging.info(msg)

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    logging.basicConfig(
        filename="firewall_day1.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )

    print("🚀 Personal Firewall Day 1 (Monitoring) started. Press Ctrl+C to stop.")
    rules = load_rules()
    sniff(prn=packet_callback, store=False)
Sample rules.json for Day 1:
{
  "block_ips": ["192.168.1.7"],
  "block_ports": [80],
  "allow_protocols": ["TCP"]
}
Process / Explanation

Detected local IPs to identify incoming vs outgoing packets.

Loaded a rules JSON file containing blocked IPs, ports, and protocols.

Monitored all packets using Scapy’s sniff().

Matched each packet against rules and logged [ALLOWED] or [BLOCKED].

Logged results in firewall_day1.log for review.
Day 2 – Enforcing Firewall

Goal:

Enforce firewall rules at kernel level using iptables.

Block specific IPs, ports, and ICMP (ping).

Log all activity in real-time.

Python Script: firewall_day2.py
#!/usr/bin/env python3
"""
Personal Firewall - Day 2 (Enforcing Firewall)
-----------------------------------------------
- Monitors packets with Scapy
- Injects iptables rules to block IPs, ports, and ICMP
- Logs all packet activity with BLOCKED/ALLOWED tags
- Cleans up iptables rules on exit
"""

import json
import logging
import socket
import subprocess
import signal
import sys
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.inet import ICMP

RULES_PATH = "rules.json"
ADDED_RULES = []

# -------------------------
# Helpers
# -------------------------
def load_rules(path=RULES_PATH):
    with open(path) as f:
        return json.load(f)

def run_cmd(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def rule_exists(cmd_base):
    rc, _, _ = run_cmd(["sudo", "iptables", "-C"] + cmd_base)
    return rc == 0

def add_rule(cmd_base):
    if rule_exists(cmd_base):
        return False
    rc, _, err = run_cmd(["sudo", "-S", "iptables", "-A"] + cmd_base)
    if rc == 0:
        ADDED_RULES.append(cmd_base)
        print(f"[iptables] added: {' '.join(cmd_base)}")
        return True
    else:
        print(f"[iptables] failed to add: {' '.join(cmd_base)}; err: {err}")
        return False

def delete_rule(cmd_base):
    run_cmd(["sudo", "iptables", "-D"] + cmd_base)

def cleanup_rules():
    print("Cleaning up iptables rules...")
    for cmd in reversed(ADDED_RULES):
        delete_rule(cmd)
    ADDED_RULES.clear()

# -------------------------
# Rule Enforcement
# -------------------------
def block_ip(ip):
    add_rule(["INPUT", "-s", ip, "-j", "DROP"])
    add_rule(["OUTPUT", "-d", ip, "-j", "DROP"])

def block_port(port):
    for proto in ["tcp", "udp"]:
        add_rule(["INPUT", "-p", proto, "--dport", str(port), "-j", "DROP"])
        add_rule(["OUTPUT", "-p", proto, "--dport", str(port), "-j", "DROP"])

def block_icmp():
    add_rule(["INPUT", "-p", "icmp", "-j", "DROP"])
    add_rule(["OUTPUT", "-p", "icmp", "-j", "DROP"])

def apply_rules(rules):
    for ip in rules.get("block_ips", []):
        block_ip(ip)
    for port in rules.get("block_ports", []):
        block_port(port)
    for proto in rules.get("block_protocols", []):
        if proto.upper() == "ICMP":
            block_icmp()

# -------------------------
# Direction Detection & Logging
# -------------------------
def get_local_ips():
    ips = []
    hostname = socket.gethostname()
    try:
        ips.append(socket.gethostbyname(hostname))
    except socket.gaierror:
        pass
    ips.extend(["127.0.0.1", "0.0.0.0"])
    return ips

LOCAL_IPS = get_local_ips()

def get_direction(packet):
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        if src in LOCAL_IPS:
            return "outgoing"
        elif dst in LOCAL_IPS:
            return "incoming"
    return "unknown"

def match_rules(packet, rules):
    try:
        if IP in packet and packet[IP].src in rules.get("block_ips", []):
            return False
        if TCP in packet and int(packet[TCP].sport) in rules.get("block_ports", []):
            return False
        if UDP in packet and int(packet[UDP].sport) in rules.get("block_ports", []):
            return False
        if ICMP in packet and "ICMP" in rules.get("block_protocols", []):
            return False
    except Exception as e:
        logging.error(f"Rule matching error: {e}")
    return True

def packet_callback(packet):
    direction = get_direction(packet)
    action = "ALLOWED" if match_rules(packet, RULES) else "BLOCKED"
    msg = f"[{action}] {direction} {packet.summary()}"
    print(msg)
    logging.info(msg)

# -------------------------
# Signal Handler
# -------------------------
def on_exit(signum, frame):
    cleanup_rules()
    sys.exit(0)

signal.signal(signal.SIGINT, on_exit)
signal.signal(signal.SIGTERM, on_exit)

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    logging.basicConfig(
        filename="firewall_day2.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )

    print("🚀 Personal Firewall Day 2 (Enforcing) started. Press Ctrl+C to stop.")
    print(f"Local IPs detected: {LOCAL_IPS}")

    RULES = load_rules(RULES_PATH)
    print("Loaded rules:", RULES)

    apply_rules(RULES)
    sniff(prn=packet_callback, store=False)
Sample rules.json for Day 2:
{
  "block_ips": ["192.168.1.7"],
  "block_ports": [80],
  "block_protocols": ["ICMP"]
}
Process / Explanation

Loaded rules and applied iptables rules for:

Blocking IPs (INPUT/OUTPUT)

Blocking ports (TCP & UDP)

Blocking ICMP (all ping requests)

Packet sniffing continues in real-time and logs [BLOCKED] or [ALLOWED].

Cleaned up rules on exit using SIGINT or SIGTERM.

Verified via:

ping -4 8.8.8.8 → blocked

curl http://192.168.1.7 → blocked

sudo iptables -L -v -n → counters increase on DROP rules

