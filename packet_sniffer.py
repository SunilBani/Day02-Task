#!/usr/bin/env python3
# packet_sniffer.py
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import Counter
import matplotlib.pyplot as plt
import sys

# === Configuration ===
IFACE = sys.argv[1] if len(sys.argv) > 1 else "lo"   # default to loopback if not provided
PACKET_COUNT = 100
PCAP_FILE = "outputs/capture.pcap"
CHART_FILE = "outputs/protocol_distribution.png"

print(f"[+] Interface: {IFACE}")
print(f"[+] Capturing {PACKET_COUNT} packets... (run as root)")

pkts = sniff(iface=IFACE, count=PACKET_COUNT, store=True)
wrpcap(PCAP_FILE, pkts)
print(f"[+] Saved capture to {PCAP_FILE}")

protocols = []
for pkt in pkts:
    if IP in pkt:
        if pkt.haslayer(TCP):
            protocols.append("TCP")
        elif pkt.haslayer(UDP):
            protocols.append("UDP")
        elif pkt.haslayer(ICMP):
            protocols.append("ICMP")
        else:
            protocols.append("Other-IP")
    else:
        if pkt.haslayer("ARP"):
            protocols.append("ARP")
        else:
            protocols.append("Non-IP")

counts = Counter(protocols)
print("[+] Protocol counts:", counts)

# create bar chart
labels = list(counts.keys())
values = [counts[k] for k in labels]

plt.figure(figsize=(8,5))
plt.bar(labels, values)
plt.title("Protocol Distribution in Captured Packets")
plt.xlabel("Protocol")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(CHART_FILE)
print(f"[+] Chart saved to {CHART_FILE}")

