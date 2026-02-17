#!/usr/bin/env python3
"""Generate paired synthetic pcap files for comparative analysis testing.

Each function creates a (Capture A, Capture B) pair representing a
before/after scenario. Uses the same helpers and conventions as
generate_test_pcaps.py. Requires: pip install scapy

Usage:
    cd tests && python generate_compare_test_pcaps.py
    # Creates tests/sample_pcaps/compare/ with 16 pcap files (8 pairs)
"""
from __future__ import annotations

import random
import string
from pathlib import Path

from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, TCP, UDP, Raw,
    wrpcap, conf,
)

# Suppress scapy warnings
conf.verb = 0

OUTPUT_DIR = Path(__file__).parent / "sample_pcaps" / "compare"
BASE_TIME = 1700000000.0

# Consistent MAC/IP addresses
CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
ROUTER_MAC = "aa:bb:cc:dd:ee:03"
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
ROUTER_IP = "10.0.0.254"
DNS_SERVER_IP = "10.0.0.53"
TARGET_IP = "10.0.0.5"


def _ts(offset: float) -> float:
    return BASE_TIME + offset


def _tcp_stream(client_ip=CLIENT_IP, server_ip=SERVER_IP,
                sport=12345, dport=80,
                client_mac=CLIENT_MAC, server_mac=SERVER_MAC,
                start_time=0.0, data_packets=5, teardown="fin"):
    """Build a complete TCP stream. Returns list of (packet, timestamp) tuples."""
    pkts = []
    t = start_time
    seq_c = 1000
    seq_s = 2000

    # SYN
    pkts.append((
        Ether(src=client_mac, dst=server_mac) /
        IP(src=client_ip, dst=server_ip) /
        TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
        _ts(t)
    ))
    t += 0.001; seq_c += 1

    # SYN-ACK
    pkts.append((
        Ether(src=server_mac, dst=client_mac) /
        IP(src=server_ip, dst=client_ip) /
        TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
        _ts(t)
    ))
    t += 0.001; seq_s += 1

    # ACK
    pkts.append((
        Ether(src=client_mac, dst=server_mac) /
        IP(src=client_ip, dst=server_ip) /
        TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
        _ts(t)
    ))
    t += 0.001

    # Data packets
    for i in range(data_packets):
        pkts.append((
            Ether(src=client_mac, dst=server_mac) /
            IP(src=client_ip, dst=server_ip) /
            TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
            Raw(load=b"X" * 100),
            _ts(t)
        ))
        seq_c += 100
        t += 0.005
        pkts.append((
            Ether(src=server_mac, dst=client_mac) /
            IP(src=server_ip, dst=client_ip) /
            TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=65535),
            _ts(t)
        ))
        t += 0.001

    # Teardown
    if teardown == "fin":
        pkts.append((
            Ether(src=client_mac, dst=server_mac) /
            IP(src=client_ip, dst=server_ip) /
            TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s, window=65535),
            _ts(t)
        ))
        t += 0.001
        pkts.append((
            Ether(src=server_mac, dst=client_mac) /
            IP(src=server_ip, dst=client_ip) /
            TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1, window=65535),
            _ts(t)
        ))
        t += 0.001
        pkts.append((
            Ether(src=client_mac, dst=server_mac) /
            IP(src=client_ip, dst=server_ip) /
            TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=65535),
            _ts(t)
        ))
    elif teardown == "rst":
        pkts.append((
            Ether(src=server_mac, dst=client_mac) /
            IP(src=server_ip, dst=client_ip) /
            TCP(sport=dport, dport=sport, flags="R", seq=seq_s, window=0),
            _ts(t)
        ))

    return pkts


def _dns_pair(qname, dns_id, query_time, response_delay=0.015,
              rcode=0, qtype=1, client_ip=CLIENT_IP,
              dns_server=DNS_SERVER_IP, has_response=True):
    """Build a DNS query + response pair."""
    pkts = []
    sport = 50000 + (dns_id & 0x0FFF)
    pkts.append((
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
        IP(src=client_ip, dst=dns_server) /
        UDP(sport=sport, dport=53) /
        DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype)),
        _ts(query_time)
    ))

    if has_response:
        an = None
        ancount = 0
        if rcode == 0 and qtype == 1:
            an = DNSRR(rrname=qname, type="A", rdata="93.184.216.34", ttl=300)
            ancount = 1
        dns_layer = DNS(id=dns_id, qr=1, rd=1, ra=1, rcode=rcode,
                        qd=DNSQR(qname=qname, qtype=qtype),
                        an=an, ancount=ancount)
        pkts.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=dns_server, dst=client_ip) /
            UDP(sport=53, dport=sport) /
            dns_layer,
            _ts(query_time + response_delay)
        ))

    return pkts


def _write_pcap(name: str, pkt_ts_list: list[tuple]) -> tuple[Path, int]:
    """Write packets with timestamps to pcap."""
    path = OUTPUT_DIR / name
    packets = []
    for pkt, ts in sorted(pkt_ts_list, key=lambda x: x[1]):
        pkt.time = ts
        packets.append(pkt)
    wrpcap(str(path), packets)
    return path, len(packets)


def _healthy_baseline(start_time=0.0):
    """Generate a set of healthy traffic packets (reused across pairs)."""
    pkts = []
    t = start_time

    # ARP: 5 request/reply pairs
    for i in range(5):
        tip = f"10.0.0.{10 + i}"
        tmac = f"aa:bb:cc:dd:ee:{10 + i:02x}"
        pkts.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=tip),
            _ts(t)
        ))
        pkts.append((
            Ether(src=tmac, dst=CLIENT_MAC) /
            ARP(op=2, hwsrc=tmac, psrc=tip, pdst=CLIENT_IP),
            _ts(t + 0.001)
        ))
        t += 0.5

    # ICMP: 10 echo pairs at ~5ms
    for i in range(10):
        pkts.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        pkts.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=i + 1),
            _ts(t + 0.005)
        ))
        t += 0.1

    # TCP: 1 clean stream
    pkts.extend(_tcp_stream(start_time=t, data_packets=3))
    t += 2.0

    # DNS: 10 query/response pairs, all NOERROR ~15ms
    for i in range(10):
        pkts.extend(_dns_pair(f"host{i}.example.com", 0x1000 + i, t, 0.015))
        t += 0.2

    return pkts


# ---------------------------------------------------------------------------
# Comparison pair generators
# ---------------------------------------------------------------------------

def gen_healthy_stable():
    """Both captures are healthy — expect all STABLE assessments."""
    pkts_a = _healthy_baseline(start_time=0.0)
    pkts_b = _healthy_baseline(start_time=0.0)
    path_a, count_a = _write_pcap("healthy_stable_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("healthy_stable_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, "Both healthy — all STABLE"


def gen_tcp_degradation():
    """A: Healthy TCP. B: TCP with retransmissions + dup ACKs."""
    # Capture A — clean
    pkts_a = _healthy_baseline(start_time=0.0)

    # Capture B — same baseline but TCP stream has retransmissions
    pkts_b = []
    t = 0.0

    # Same ARP
    for i in range(5):
        tip = f"10.0.0.{10 + i}"
        tmac = f"aa:bb:cc:dd:ee:{10 + i:02x}"
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=tip),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src=tmac, dst=CLIENT_MAC) /
            ARP(op=2, hwsrc=tmac, psrc=tip, pdst=CLIENT_IP),
            _ts(t + 0.001)
        ))
        t += 0.5

    # Same ICMP
    for i in range(10):
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=i + 1),
            _ts(t + 0.005)
        ))
        t += 0.1

    # TCP with retransmissions
    sport, dport = 12345, 80
    seq_c, seq_s = 1000, 2000
    pkts_b.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                   IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                   _ts(t)))
    t += 0.001; seq_c += 1
    pkts_b.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                   IP(src=SERVER_IP, dst=CLIENT_IP) /
                   TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                   _ts(t)))
    t += 0.001; seq_s += 1
    pkts_b.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                   IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                   _ts(t)))
    t += 0.001

    for i in range(8):
        pkts_b.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                       IP(src=CLIENT_IP, dst=SERVER_IP) /
                       TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                       Raw(load=b"D" * 100), _ts(t)))
        t += 0.01
        # Retransmit every other packet
        if i % 2 == 0:
            pkts_b.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                           IP(src=CLIENT_IP, dst=SERVER_IP) /
                           TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                           Raw(load=b"D" * 100), _ts(t)))
            t += 0.2
        seq_c += 100
        pkts_b.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                       IP(src=SERVER_IP, dst=CLIENT_IP) /
                       TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=65535),
                       _ts(t)))
        t += 0.001
    pkts_b.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                   IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s, window=65535),
                   _ts(t)))
    t += 2.0

    # Same DNS
    for i in range(10):
        pkts_b.extend(_dns_pair(f"host{i}.example.com", 0x1000 + i, t, 0.015))
        t += 0.2

    path_a, count_a = _write_pcap("tcp_degradation_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("tcp_degradation_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, "TCP REGRESSION: retransmissions in B"


def gen_dns_new_nxdomain():
    """A: Clean DNS. B: DNS with DGA-like NXDOMAIN names."""
    pkts_a = _healthy_baseline(start_time=0.0)

    pkts_b = _healthy_baseline(start_time=0.0)

    # Add DGA-like NXDOMAIN queries to B
    random.seed(42)
    t = 15.0
    for i in range(10):
        rand_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        qname = f"{rand_name}.evil-c2.com"
        pkts_b.extend(_dns_pair(qname, 0x3000 + i, t, 0.020, rcode=3))
        t += 0.2

    path_a, count_a = _write_pcap("dns_new_nxdomain_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("dns_new_nxdomain_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, "NEW ISSUE: CRITICAL DGA NXDOMAIN in B"


def gen_arp_spoofing_start():
    """A: Clean ARP. B: ARP with IP-MAC conflict (spoofing starts)."""
    pkts_a = _healthy_baseline(start_time=0.0)

    pkts_b = _healthy_baseline(start_time=0.0)

    # Add ARP spoofing to B
    spoofed_ip = TARGET_IP
    mac_legit = "aa:bb:cc:dd:ee:05"
    mac_attacker = "ff:ee:dd:cc:bb:aa"
    t = 15.0
    for i in range(5):
        pkts_b.append((
            Ether(src=mac_legit, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=mac_legit, psrc=spoofed_ip, pdst=CLIENT_IP),
            _ts(t)
        ))
        t += 0.1
    for i in range(5):
        pkts_b.append((
            Ether(src=mac_attacker, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=mac_attacker, psrc=spoofed_ip, pdst=CLIENT_IP),
            _ts(t)
        ))
        t += 0.1

    path_a, count_a = _write_pcap("arp_spoofing_start_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("arp_spoofing_start_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, "NEW ISSUE: CRITICAL ARP spoofing in B"


def gen_arp_spoofing_resolved():
    """A: ARP with IP-MAC conflict. B: Clean ARP (spoofing resolved)."""
    # A has spoofing
    pkts_a = _healthy_baseline(start_time=0.0)
    spoofed_ip = TARGET_IP
    mac_legit = "aa:bb:cc:dd:ee:05"
    mac_attacker = "ff:ee:dd:cc:bb:aa"
    t = 15.0
    for i in range(5):
        pkts_a.append((
            Ether(src=mac_legit, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=mac_legit, psrc=spoofed_ip, pdst=CLIENT_IP),
            _ts(t)
        ))
        t += 0.1
    for i in range(5):
        pkts_a.append((
            Ether(src=mac_attacker, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=mac_attacker, psrc=spoofed_ip, pdst=CLIENT_IP),
            _ts(t)
        ))
        t += 0.1

    # B is clean
    pkts_b = _healthy_baseline(start_time=0.0)

    path_a, count_a = _write_pcap("arp_spoofing_resolved_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("arp_spoofing_resolved_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, "RESOLVED: ARP spoofing from A absent in B"


def gen_icmp_rtt_regression():
    """A: Low RTT pings. B: High RTT pings — latency regression."""
    pkts_a = _healthy_baseline(start_time=0.0)

    # B has same traffic but ICMP RTT is much higher
    pkts_b = []
    t = 0.0

    # Same ARP
    for i in range(5):
        tip = f"10.0.0.{10 + i}"
        tmac = f"aa:bb:cc:dd:ee:{10 + i:02x}"
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=tip),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src=tmac, dst=CLIENT_MAC) /
            ARP(op=2, hwsrc=tmac, psrc=tip, pdst=CLIENT_IP),
            _ts(t + 0.001)
        ))
        t += 0.5

    # ICMP with high RTT (~150ms instead of 5ms)
    for i in range(10):
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=i + 1),
            _ts(t + 0.150)
        ))
        t += 0.3

    # Same TCP
    pkts_b.extend(_tcp_stream(start_time=t, data_packets=3))
    t += 2.0

    # Same DNS
    for i in range(10):
        pkts_b.extend(_dns_pair(f"host{i}.example.com", 0x1000 + i, t, 0.015))
        t += 0.2

    path_a, count_a = _write_pcap("icmp_rtt_regression_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("icmp_rtt_regression_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, "REGRESSION: ICMP RTT 5ms -> 150ms"


def gen_host_goes_down():
    """A: Host responds. B: ARP unanswered + ICMP unreachable for same IP."""
    down_ip = "10.0.0.99"
    down_mac = "aa:bb:cc:dd:ee:99"

    # A — host is up, responds to ARP and ping
    pkts_a = _healthy_baseline(start_time=0.0)
    t = 15.0
    for i in range(5):
        pkts_a.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=down_ip),
            _ts(t)
        ))
        pkts_a.append((
            Ether(src=down_mac, dst=CLIENT_MAC) /
            ARP(op=2, hwsrc=down_mac, psrc=down_ip, pdst=CLIENT_IP),
            _ts(t + 0.001)
        ))
        t += 0.5
    for i in range(5):
        pkts_a.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=down_ip) /
            ICMP(type=8, code=0, seq=100 + i),
            _ts(t)
        ))
        pkts_a.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=down_ip, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=100 + i),
            _ts(t + 0.005)
        ))
        t += 0.2

    # B — host is down
    pkts_b = _healthy_baseline(start_time=0.0)
    t = 15.0
    # ARP unanswered
    for i in range(5):
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=down_ip),
            _ts(t)
        ))
        t += 0.5
    # ICMP Host Unreachable from router
    for i in range(5):
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
            IP(src=CLIENT_IP, dst=down_ip) /
            ICMP(type=8, code=0, seq=100 + i),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
            IP(src=ROUTER_IP, dst=CLIENT_IP) /
            ICMP(type=3, code=1) /
            IP(src=CLIENT_IP, dst=down_ip) /
            ICMP(type=8, code=0, seq=100 + i),
            _ts(t + 0.002)
        ))
        t += 0.3

    path_a, count_a = _write_pcap("host_goes_down_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("host_goes_down_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, \
        f"NEW ISSUE: host {down_ip} down (ARP unanswered + ICMP unreachable)"


def gen_mixed_improvements():
    """A: Multiple issues. B: Some resolved, some remain."""
    # A has: ARP unanswered, high-RTT ICMP, TCP retransmissions, DNS slow
    pkts_a = []
    t = 0.0

    # ARP unanswered for 10.0.0.99
    for i in range(5):
        pkts_a.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst="10.0.0.99"),
            _ts(t)
        ))
        t += 0.5

    # ICMP with high RTT
    for i in range(10):
        pkts_a.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        pkts_a.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=i + 1),
            _ts(t + 0.200)
        ))
        t += 0.3

    # TCP with retransmissions
    sport, dport = 12345, 80
    seq_c, seq_s = 1000, 2000
    pkts_a.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                   IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                   _ts(t)))
    t += 0.001; seq_c += 1
    pkts_a.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                   IP(src=SERVER_IP, dst=CLIENT_IP) /
                   TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                   _ts(t)))
    t += 0.001; seq_s += 1
    pkts_a.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                   IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                   _ts(t)))
    t += 0.001
    for i in range(5):
        pkts_a.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                       IP(src=CLIENT_IP, dst=SERVER_IP) /
                       TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                       Raw(load=b"R" * 100), _ts(t)))
        t += 0.01
        # Retransmit
        pkts_a.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                       IP(src=CLIENT_IP, dst=SERVER_IP) /
                       TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                       Raw(load=b"R" * 100), _ts(t)))
        t += 0.2
        seq_c += 100
        pkts_a.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                       IP(src=SERVER_IP, dst=CLIENT_IP) /
                       TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=65535),
                       _ts(t)))
        t += 0.001
    pkts_a.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                   IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s, window=65535),
                   _ts(t)))
    t += 2.0

    # DNS with slow queries
    for i in range(10):
        delay = 0.500 if i < 3 else 0.015
        pkts_a.extend(_dns_pair(f"host{i}.example.com", 0x1000 + i, t, delay))
        t += 0.6

    # B: ARP resolved, ICMP still high-RTT, TCP clean, DNS still slow
    pkts_b = []
    t = 0.0

    # ARP now answered (resolved)
    for i in range(5):
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst="10.0.0.99"),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src="aa:bb:cc:dd:ee:99", dst=CLIENT_MAC) /
            ARP(op=2, hwsrc="aa:bb:cc:dd:ee:99", psrc="10.0.0.99", pdst=CLIENT_IP),
            _ts(t + 0.001)
        ))
        t += 0.5

    # ICMP still high RTT (remains)
    for i in range(10):
        pkts_b.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        pkts_b.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=i + 1),
            _ts(t + 0.200)
        ))
        t += 0.3

    # TCP clean now (resolved)
    pkts_b.extend(_tcp_stream(start_time=t, data_packets=5))
    t += 2.0

    # DNS still slow (remains)
    for i in range(10):
        delay = 0.500 if i < 3 else 0.015
        pkts_b.extend(_dns_pair(f"host{i}.example.com", 0x1000 + i, t, delay))
        t += 0.6

    path_a, count_a = _write_pcap("mixed_improvements_a.pcap", pkts_a)
    path_b, count_b = _write_pcap("mixed_improvements_b.pcap", pkts_b)
    return path_a, path_b, count_a, count_b, \
        "Mix: ARP + TCP RESOLVED, ICMP + DNS STABLE (still degraded)"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

GENERATORS = [
    ("healthy_stable", gen_healthy_stable),
    ("tcp_degradation", gen_tcp_degradation),
    ("dns_new_nxdomain", gen_dns_new_nxdomain),
    ("arp_spoofing_start", gen_arp_spoofing_start),
    ("arp_spoofing_resolved", gen_arp_spoofing_resolved),
    ("icmp_rtt_regression", gen_icmp_rtt_regression),
    ("host_goes_down", gen_host_goes_down),
    ("mixed_improvements", gen_mixed_improvements),
]


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating {len(GENERATORS)} comparison pairs in {OUTPUT_DIR}/\n")

    results = []
    for name, gen_func in GENERATORS:
        path_a, path_b, count_a, count_b, desc = gen_func()
        results.append((name, count_a, count_b, desc))

    max_name = max(len(r[0]) for r in results)
    for name, count_a, count_b, desc in results:
        print(f"  {name:<{max_name}}  A:{count_a:>4}  B:{count_b:>4}  {desc}")

    total_files = len(results) * 2
    print(f"\nGenerated {total_files} pcaps ({len(results)} pairs) in {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
