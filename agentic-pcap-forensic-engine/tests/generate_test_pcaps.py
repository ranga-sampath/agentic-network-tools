#!/usr/bin/env python3
"""Generate synthetic test pcap files for the PCAP Forensic Engine.

Each function creates a pcap targeting specific anomaly scenarios.
All pcaps use consistent Ether framing and a fixed base_time for
reproducibility. Requires: pip install scapy

Usage:
    cd tests && python generate_test_pcaps.py
    # Creates tests/sample_pcaps/ with ~23 pcap files
"""
from __future__ import annotations

import os
import random
import string
from pathlib import Path

from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, TCP, UDP, Raw,
    wrpcap, conf,
)

# Suppress scapy warnings
conf.verb = 0

OUTPUT_DIR = Path(__file__).parent / "sample_pcaps"
BASE_TIME = 1700000000.0  # Fixed epoch for reproducibility

# Consistent MAC/IP addresses used across scenarios
CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
ROUTER_MAC = "aa:bb:cc:dd:ee:03"
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
ROUTER_IP = "10.0.0.254"
DNS_SERVER_IP = "10.0.0.53"
TARGET_IP = "10.0.0.5"


def _ts(offset: float) -> float:
    """Return base_time + offset for consistent timestamps."""
    return BASE_TIME + offset


def _ether(src=CLIENT_MAC, dst=SERVER_MAC):
    return Ether(src=src, dst=dst)


# ---------------------------------------------------------------------------
# Helper: build TCP handshake + data + teardown packets
# ---------------------------------------------------------------------------

def _tcp_stream(client_ip=CLIENT_IP, server_ip=SERVER_IP,
                sport=12345, dport=80,
                client_mac=CLIENT_MAC, server_mac=SERVER_MAC,
                start_time=0.0, data_packets=5, teardown="fin"):
    """Build a complete TCP stream: SYN, SYN-ACK, ACK, data, FIN/RST.
    Returns list of (packet, timestamp) tuples."""
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
    t += 0.001
    seq_c += 1

    # SYN-ACK
    pkts.append((
        Ether(src=server_mac, dst=client_mac) /
        IP(src=server_ip, dst=client_ip) /
        TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
        _ts(t)
    ))
    t += 0.001
    seq_s += 1

    # ACK (completes handshake)
    pkts.append((
        Ether(src=client_mac, dst=server_mac) /
        IP(src=client_ip, dst=server_ip) /
        TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
        _ts(t)
    ))
    t += 0.001

    # Data packets
    for i in range(data_packets):
        payload = Raw(load=b"X" * 100)
        pkts.append((
            Ether(src=client_mac, dst=server_mac) /
            IP(src=client_ip, dst=server_ip) /
            TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
            payload,
            _ts(t)
        ))
        seq_c += 100
        t += 0.005

        # ACK from server
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
              dns_server=DNS_SERVER_IP, truncated=False,
              has_response=True):
    """Build a DNS query + response pair. Returns list of (pkt, ts) tuples."""
    pkts = []
    sport = 50000 + (dns_id & 0x0FFF)
    # Query
    pkts.append((
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
        IP(src=client_ip, dst=dns_server) /
        UDP(sport=sport, dport=53) /
        DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype)),
        _ts(query_time)
    ))

    if has_response:
        # Response
        an = None
        ancount = 0
        if rcode == 0 and qtype == 1:
            an = DNSRR(rrname=qname, type="A", rdata="93.184.216.34", ttl=300)
            ancount = 1

        dns_layer = DNS(id=dns_id, qr=1, rd=1, ra=1, rcode=rcode,
                        qd=DNSQR(qname=qname, qtype=qtype),
                        an=an, ancount=ancount)
        if truncated:
            dns_layer.tc = 1

        pkts.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=dns_server, dst=client_ip) /
            UDP(sport=53, dport=sport) /
            dns_layer,
            _ts(query_time + response_delay)
        ))

    return pkts


def _write_pcap(name: str, pkt_ts_list: list[tuple], description: str) -> tuple[Path, int]:
    """Write packets with timestamps to pcap. Returns (path, packet_count)."""
    path = OUTPUT_DIR / name
    packets = []
    for pkt, ts in sorted(pkt_ts_list, key=lambda x: x[1]):
        pkt.time = ts
        packets.append(pkt)
    wrpcap(str(path), packets)
    return path, len(packets)


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

def gen_healthy_small():
    """Baseline healthy traffic — all protocols, no anomalies."""
    pkts = []

    # ARP: 5 request/reply pairs (all answered)
    for i in range(5):
        t = i * 0.5
        target_ip = f"10.0.0.{10 + i}"
        target_mac = f"aa:bb:cc:dd:ee:{10 + i:02x}"
        pkts.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=target_ip),
            _ts(t)
        ))
        pkts.append((
            Ether(src=target_mac, dst=CLIENT_MAC) /
            ARP(op=2, hwsrc=target_mac, psrc=target_ip, pdst=CLIENT_IP),
            _ts(t + 0.001)
        ))

    # ICMP: 10 echo pairs at ~5ms RTT
    for i in range(10):
        t = 3.0 + i * 0.1
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

    # TCP: 1 clean stream
    pkts.extend(_tcp_stream(start_time=5.0, data_packets=3))

    # DNS: 10 query/response pairs, all NOERROR ~15ms
    for i in range(10):
        t = 8.0 + i * 0.2
        pkts.extend(_dns_pair(f"host{i}.example.com", 0x1000 + i, t, 0.015))

    return _write_pcap("healthy_small.pcap", pkts,
                       "no anomalies — baseline healthy traffic")


def gen_healthy_large():
    """Larger baseline — ~500 packets, no anomalies."""
    pkts = []

    # ARP: 20 req/reply pairs
    for i in range(20):
        t = i * 0.2
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

    # ICMP: 50 echo pairs at ~5ms
    for i in range(50):
        t = 5.0 + i * 0.05
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

    # TCP: 5 clean streams
    for s in range(5):
        pkts.extend(_tcp_stream(
            sport=12345 + s, start_time=8.0 + s * 2.0, data_packets=10
        ))

    # DNS: 50 query/response pairs
    for i in range(50):
        t = 20.0 + i * 0.1
        pkts.extend(_dns_pair(f"host{i}.example.com", 0x2000 + i, t, 0.015))

    return _write_pcap("healthy_large.pcap", pkts,
                       "no anomalies — larger baseline (~500 pkts)")


def gen_arp_spoofing():
    """Two different MACs claiming the same IP — ARP spoofing indicator."""
    pkts = []
    spoofed_ip = TARGET_IP
    mac_legit = "aa:bb:cc:dd:ee:05"
    mac_attacker = "ff:ee:dd:cc:bb:aa"

    # Legitimate ARP replies from real host
    for i in range(8):
        pkts.append((
            Ether(src=mac_legit, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=mac_legit, psrc=spoofed_ip, pdst=CLIENT_IP),
            _ts(i * 0.5)
        ))

    # Attacker ARP replies claiming same IP
    for i in range(8):
        pkts.append((
            Ether(src=mac_attacker, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=mac_attacker, psrc=spoofed_ip, pdst=CLIENT_IP),
            _ts(0.1 + i * 0.5)
        ))

    # Some normal ARP requests
    for i in range(4):
        pkts.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=spoofed_ip),
            _ts(0.05 + i * 1.0)
        ))

    return _write_pcap("arp_spoofing.pcap", pkts,
                       f"IP-MAC conflict for {spoofed_ip}")


def gen_arp_unanswered():
    """ARP requests with no replies — host unreachable at L2."""
    pkts = []
    for i in range(10):
        pkts.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=TARGET_IP),
            _ts(i * 0.5)
        ))
    return _write_pcap("arp_unanswered.pcap", pkts,
                       f"5+ unanswered ARP requests for {TARGET_IP}")


def gen_icmp_unreachable_host():
    """ICMP Type 3, Code 1 — Host Unreachable."""
    pkts = []
    target = "10.0.0.99"

    for i in range(10):
        t = i * 0.2
        # Echo request to unreachable host
        pkts.append((
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
            IP(src=CLIENT_IP, dst=target) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        # Router responds with Host Unreachable
        pkts.append((
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
            IP(src=ROUTER_IP, dst=CLIENT_IP) /
            ICMP(type=3, code=1) /
            IP(src=CLIENT_IP, dst=target) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t + 0.002)
        ))

    return _write_pcap("icmp_unreachable_host.pcap", pkts,
                       f"Type 3 Code 1 (Host Unreachable) for {target}")


def gen_icmp_unreachable_port():
    """ICMP Type 3, Code 3 — Port Unreachable."""
    pkts = []
    for i in range(7):
        t = i * 0.3
        # UDP to closed port
        pkts.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            UDP(sport=5000 + i, dport=161),
            _ts(t)
        ))
        # Port Unreachable response
        pkts.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=3, code=3) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            UDP(sport=5000 + i, dport=161),
            _ts(t + 0.001)
        ))

    return _write_pcap("icmp_unreachable_port.pcap", pkts,
                       "Type 3 Code 3 (Port Unreachable) — SNMP port 161")


def gen_icmp_pmtud_blackhole():
    """ICMP Type 3, Code 4 — Fragmentation Needed / DF Set (PMTUD)."""
    pkts = []
    for i in range(7):
        t = i * 0.2
        # Large packet with DF bit
        pkts.append((
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
            IP(src=CLIENT_IP, dst="192.168.1.50", flags="DF") /
            TCP(sport=12345, dport=443, flags="A", seq=1000 + i * 1400) /
            Raw(load=b"X" * 1400),
            _ts(t)
        ))
        # Frag Needed response from router
        pkts.append((
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
            IP(src=ROUTER_IP, dst=CLIENT_IP) /
            ICMP(type=3, code=4, nexthopmtu=1280) /
            IP(src=CLIENT_IP, dst="192.168.1.50", flags="DF") /
            TCP(sport=12345, dport=443, flags="A"),
            _ts(t + 0.001)
        ))

    return _write_pcap("icmp_pmtud_blackhole.pcap", pkts,
                       "Type 3 Code 4 (Frag Needed/DF Set) — PMTUD issue")


def gen_icmp_redirect():
    """ICMP Type 5 — Redirect messages from router."""
    pkts = []
    alt_gateway = "10.0.0.253"
    for i in range(5):
        t = i * 0.5
        # Normal traffic
        pkts.append((
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
            IP(src=CLIENT_IP, dst="192.168.1.50") /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        # Router sends redirect — use different gateway
        pkts.append((
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
            IP(src=ROUTER_IP, dst=CLIENT_IP) /
            ICMP(type=5, code=1, gw=alt_gateway) /
            IP(src=CLIENT_IP, dst="192.168.1.50") /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t + 0.001)
        ))

    return _write_pcap("icmp_redirect.pcap", pkts,
                       f"Type 5 (Redirect) from {ROUTER_IP}")


def gen_icmp_ttl_exceeded():
    """ICMP Type 11 — TTL Exceeded, same source = routing loop indicator."""
    pkts = []
    loop_router = "172.16.0.1"
    target = "192.168.99.1"

    for i in range(10):
        t = i * 0.1
        # Packet with low TTL heading into loop
        pkts.append((
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
            IP(src=CLIENT_IP, dst=target, ttl=2) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        # Same router keeps sending TTL exceeded (loop indicator)
        pkts.append((
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
            IP(src=loop_router, dst=CLIENT_IP) /
            ICMP(type=11, code=0) /
            IP(src=CLIENT_IP, dst=target, ttl=1) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t + 0.005)
        ))

    return _write_pcap("icmp_ttl_exceeded.pcap", pkts,
                       f"Type 11 (TTL Exceeded) from {loop_router} — routing loop")


def gen_icmp_high_rtt():
    """Some pings with RTT > 2x median — latency anomaly."""
    pkts = []
    # 20 normal pings at ~5ms
    for i in range(20):
        t = i * 0.1
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

    # 5 high-RTT pings at ~200ms (>> 2x median of 5ms)
    for i in range(5):
        seq = 21 + i
        t = 3.0 + i * 0.3
        pkts.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            ICMP(type=8, code=0, seq=seq),
            _ts(t)
        ))
        pkts.append((
            Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
            IP(src=SERVER_IP, dst=CLIENT_IP) /
            ICMP(type=0, code=0, seq=seq),
            _ts(t + 0.200)
        ))

    return _write_pcap("icmp_high_rtt.pcap", pkts,
                       "5 pings with RTT >> 2x median (200ms vs 5ms)")


def gen_tcp_retransmissions():
    """TCP stream with retransmission packets (same seq number re-sent)."""
    pkts = []
    sport, dport = 12345, 80
    seq_c = 1000
    seq_s = 2000
    t = 0.0

    # Handshake
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_c += 1
    pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                 IP(src=SERVER_IP, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_s += 1
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                 _ts(t)))
    t += 0.001

    # Data with retransmissions (same seq = retransmit)
    for i in range(10):
        payload = Raw(load=b"D" * 100)
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                     payload, _ts(t)))
        t += 0.01

        # Retransmit the same packet (same seq) — tshark detects this
        if i % 2 == 0:
            pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                         IP(src=CLIENT_IP, dst=SERVER_IP) /
                         TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                         payload, _ts(t)))
            t += 0.2  # Retransmission after timeout

        # Server ACKs
        seq_c += 100
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=65535),
                     _ts(t)))
        t += 0.001

    # FIN teardown
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s, window=65535),
                 _ts(t)))

    return _write_pcap("tcp_retransmissions.pcap", pkts,
                       "TCP stream with retransmission packets")


def gen_tcp_zero_window():
    """TCP stream with zero-window events — receiver buffer full."""
    pkts = []
    sport, dport = 12345, 80
    seq_c = 1000
    seq_s = 2000
    t = 0.0

    # Handshake
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_c += 1
    pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                 IP(src=SERVER_IP, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_s += 1
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                 _ts(t)))
    t += 0.001

    # Data, then zero-window from server
    for i in range(5):
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                     Raw(load=b"X" * 100), _ts(t)))
        seq_c += 100
        t += 0.005

        # Server ACKs with window=0 (zero-window)
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=0),
                     _ts(t)))
        t += 0.5  # Long pause due to zero window

        # Window update — receiver ready again
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=65535),
                     _ts(t)))
        t += 0.001

    return _write_pcap("tcp_zero_window.pcap", pkts,
                       "TCP zero-window events — application bottleneck")


def gen_tcp_rst_teardown():
    """TCP connections terminated by RST instead of FIN."""
    pkts = []
    # Stream 1: SYN, SYN-ACK, ACK, data, RST
    pkts.extend(_tcp_stream(sport=11111, start_time=0.0, data_packets=3, teardown="rst"))
    # Stream 2: another RST teardown
    pkts.extend(_tcp_stream(sport=22222, start_time=2.0, data_packets=2, teardown="rst"))

    return _write_pcap("tcp_rst_teardown.pcap", pkts,
                       "TCP connections terminated by RST")


def gen_tcp_failed_handshake():
    """SYN sent but no SYN-ACK — connection fails."""
    pkts = []
    for i in range(5):
        t = i * 1.0
        # SYN
        pkts.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=30000 + i, dport=443, flags="S", seq=1000, window=65535),
            _ts(t)
        ))
        # SYN retransmit (same seq)
        pkts.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=30000 + i, dport=443, flags="S", seq=1000, window=65535),
            _ts(t + 1.0)
        ))
        # Second retransmit
        pkts.append((
            Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            TCP(sport=30000 + i, dport=443, flags="S", seq=1000, window=65535),
            _ts(t + 3.0)
        ))

    return _write_pcap("tcp_failed_handshake.pcap", pkts,
                       "SYN with no SYN-ACK — failed handshakes")


def gen_tcp_dup_acks():
    """TCP stream with duplicate ACK sequences — packet loss indicator."""
    pkts = []
    sport, dport = 12345, 80
    seq_c = 1000
    seq_s = 2000
    t = 0.0

    # Handshake
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_c += 1
    pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                 IP(src=SERVER_IP, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_s += 1
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                 _ts(t)))
    t += 0.001

    # Send several data segments
    for i in range(5):
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     TCP(sport=sport, dport=dport, flags="PA",
                         seq=seq_c + i * 100, ack=seq_s, window=65535) /
                     Raw(load=b"X" * 100), _ts(t)))
        t += 0.001

    # Server sends duplicate ACKs (acking only the first segment)
    # This happens when the server received segment 0 but is missing segment 1
    ack_val = seq_c + 100  # ACKing first 100 bytes only
    for i in range(5):
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     TCP(sport=dport, dport=sport, flags="A",
                         seq=seq_s, ack=ack_val, window=65535),
                     _ts(t)))
        t += 0.001

    # Eventually server ACKs everything
    pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                 IP(src=SERVER_IP, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="A",
                     seq=seq_s, ack=seq_c + 500, window=65535),
                 _ts(t)))

    # FIN
    t += 0.001
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="FA",
                     seq=seq_c + 500, ack=seq_s, window=65535),
                 _ts(t)))

    return _write_pcap("tcp_dup_acks.pcap", pkts,
                       "TCP duplicate ACK sequences — packet loss indicator")


def gen_dns_nxdomain():
    """DNS NXDOMAIN with DGA-like random names."""
    pkts = []
    random.seed(42)  # Reproducible random names
    for i in range(15):
        t = i * 0.2
        # Generate random DGA-like subdomain
        rand_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        qname = f"{rand_name}.evil-c2.com"
        pkts.extend(_dns_pair(qname, 0x3000 + i, t, 0.020, rcode=3))

    return _write_pcap("dns_nxdomain.pcap", pkts,
                       "NXDOMAIN with DGA-like random names")


def gen_dns_servfail():
    """DNS SERVFAIL responses — broken zone."""
    pkts = []
    domains = ["broken.internal", "db.internal", "api.internal",
               "broken.internal", "broken.internal"]
    for i, domain in enumerate(domains):
        t = i * 0.3
        pkts.extend(_dns_pair(domain, 0x4000 + i, t, 0.025, rcode=2))

    # Some normal queries too
    for i in range(5):
        t = 2.0 + i * 0.2
        pkts.extend(_dns_pair(f"ok{i}.example.com", 0x4100 + i, t, 0.015, rcode=0))

    return _write_pcap("dns_servfail.pcap", pkts,
                       "SERVFAIL responses for broken.internal")


def gen_dns_slow_queries():
    """DNS with latency outliers > 2x median."""
    pkts = []
    # 20 normal queries at ~15ms
    for i in range(20):
        t = i * 0.1
        pkts.extend(_dns_pair(f"fast{i}.example.com", 0x5000 + i, t, 0.015))

    # 5 slow queries at ~500ms
    for i in range(5):
        t = 3.0 + i * 0.6
        pkts.extend(_dns_pair(f"slow{i}.remote.com", 0x5100 + i, t, 0.500))

    return _write_pcap("dns_slow_queries.pcap", pkts,
                       "DNS latency outliers (500ms vs 15ms median)")


def gen_dns_txt_heavy():
    """High percentage of TXT queries — DNS tunneling indicator."""
    pkts = []
    random.seed(123)
    # 10 normal A queries
    for i in range(10):
        t = i * 0.1
        pkts.extend(_dns_pair(f"normal{i}.example.com", 0x6000 + i, t, 0.015, qtype=1))

    # 8 TXT queries (>20% of total = tunneling indicator)
    for i in range(8):
        t = 1.5 + i * 0.15
        encoded_data = ''.join(random.choices(string.ascii_lowercase, k=20))
        qname = f"{encoded_data}.tunnel.evil.com"
        pkts.extend(_dns_pair(qname, 0x6100 + i, t, 0.020, qtype=16, rcode=0))

    # A few more normal queries
    for i in range(5):
        t = 3.0 + i * 0.1
        pkts.extend(_dns_pair(f"legit{i}.example.com", 0x6200 + i, t, 0.015, qtype=1))

    return _write_pcap("dns_txt_heavy.pcap", pkts,
                       ">20% TXT queries — DNS tunneling indicator")


def gen_dns_unanswered():
    """DNS queries with no matching responses."""
    pkts = []
    # 5 unanswered queries
    for i in range(5):
        t = i * 0.5
        pkts.extend(_dns_pair(f"timeout{i}.example.com", 0x7000 + i, t,
                              has_response=False))

    # 5 normal answered queries
    for i in range(5):
        t = 3.0 + i * 0.2
        pkts.extend(_dns_pair(f"ok{i}.example.com", 0x7100 + i, t, 0.015))

    return _write_pcap("dns_unanswered.pcap", pkts,
                       "DNS queries with no responses")


def gen_mixed_host_down():
    """ARP unanswered + ICMP Host Unreachable for same IP — host confirmed down."""
    pkts = []
    down_ip = "10.0.0.99"

    # ARP requests for the down host — no replies
    for i in range(5):
        pkts.append((
            Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=down_ip),
            _ts(i * 0.5)
        ))

    # ICMP Host Unreachable from router for the same IP
    for i in range(5):
        t = 3.0 + i * 0.3
        pkts.append((
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
            IP(src=CLIENT_IP, dst=down_ip) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t)
        ))
        pkts.append((
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
            IP(src=ROUTER_IP, dst=CLIENT_IP) /
            ICMP(type=3, code=1) /
            IP(src=CLIENT_IP, dst=down_ip) /
            ICMP(type=8, code=0, seq=i + 1),
            _ts(t + 0.002)
        ))

    return _write_pcap("mixed_host_down.pcap", pkts,
                       f"ARP unanswered + ICMP Host Unreachable for {down_ip}")


def gen_mixed_pmtud_tcp():
    """ICMP Frag Needed + TCP retransmissions — PMTUD black hole."""
    pkts = []
    target = "192.168.1.50"
    sport, dport = 12345, 443
    t = 0.0

    # TCP handshake (works fine — small packets)
    seq_c = 1000
    seq_s = 2000
    pkts.append((Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                 IP(src=CLIENT_IP, dst=target) /
                 TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                 _ts(t)))
    t += 0.005; seq_c += 1
    pkts.append((Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                 IP(src=target, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                 _ts(t)))
    t += 0.005; seq_s += 1
    pkts.append((Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                 IP(src=CLIENT_IP, dst=target) /
                 TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                 _ts(t)))
    t += 0.005

    # Large data packets that trigger PMTUD issue
    for i in range(8):
        # Client sends large segment
        pkts.append((Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                     IP(src=CLIENT_IP, dst=target, flags="DF") /
                     TCP(sport=sport, dport=dport, flags="PA",
                         seq=seq_c, ack=seq_s, window=65535) /
                     Raw(load=b"X" * 1400), _ts(t)))
        t += 0.01

        # Router responds with Frag Needed
        pkts.append((Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                     IP(src=ROUTER_IP, dst=CLIENT_IP) /
                     ICMP(type=3, code=4, nexthopmtu=1280) /
                     IP(src=CLIENT_IP, dst=target, flags="DF") /
                     TCP(sport=sport, dport=dport, flags="PA"),
                     _ts(t)))
        t += 0.2

        # Client retransmits (same seq — tshark detects retransmission)
        pkts.append((Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                     IP(src=CLIENT_IP, dst=target, flags="DF") /
                     TCP(sport=sport, dport=dport, flags="PA",
                         seq=seq_c, ack=seq_s, window=65535) /
                     Raw(load=b"X" * 1400), _ts(t)))
        t += 0.3

        seq_c += 1400

    return _write_pcap("mixed_pmtud_tcp.pcap", pkts,
                       "ICMP Frag Needed + TCP retransmissions — PMTUD black hole")


def gen_kitchen_sink():
    """Multiple anomalies across all protocols — comprehensive test."""
    pkts = []
    t_offset = 0.0

    # === ARP section ===
    # Normal ARP pairs
    for i in range(3):
        tip = f"10.0.0.{10 + i}"
        tmac = f"aa:bb:cc:dd:ee:{10 + i:02x}"
        pkts.append((Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
                     ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=tip),
                     _ts(t_offset)))
        pkts.append((Ether(src=tmac, dst=CLIENT_MAC) /
                     ARP(op=2, hwsrc=tmac, psrc=tip, pdst=CLIENT_IP),
                     _ts(t_offset + 0.001)))
        t_offset += 0.1

    # ARP spoofing for 10.0.0.5
    for i in range(3):
        pkts.append((Ether(src="aa:bb:cc:dd:ee:05", dst="ff:ff:ff:ff:ff:ff") /
                     ARP(op=2, hwsrc="aa:bb:cc:dd:ee:05", psrc=TARGET_IP, pdst=CLIENT_IP),
                     _ts(t_offset)))
        t_offset += 0.05
    for i in range(3):
        pkts.append((Ether(src="ff:ee:dd:cc:bb:aa", dst="ff:ff:ff:ff:ff:ff") /
                     ARP(op=2, hwsrc="ff:ee:dd:cc:bb:aa", psrc=TARGET_IP, pdst=CLIENT_IP),
                     _ts(t_offset)))
        t_offset += 0.05

    # Unanswered ARP
    for i in range(3):
        pkts.append((Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
                     ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst="10.0.0.99"),
                     _ts(t_offset)))
        t_offset += 0.1

    # Gratuitous ARP
    pkts.append((Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, pdst=CLIENT_IP),
                 _ts(t_offset)))
    t_offset += 0.1

    # === ICMP section ===
    # Normal pings
    for i in range(10):
        t = t_offset + i * 0.05
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     ICMP(type=8, code=0, seq=i + 1), _ts(t)))
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     ICMP(type=0, code=0, seq=i + 1), _ts(t + 0.005)))
    t_offset += 1.0

    # High-RTT pings
    for i in range(3):
        seq = 50 + i
        t = t_offset + i * 0.3
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     ICMP(type=8, code=0, seq=seq), _ts(t)))
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     ICMP(type=0, code=0, seq=seq), _ts(t + 0.300)))
    t_offset += 1.5

    # Host Unreachable
    for i in range(3):
        t = t_offset + i * 0.1
        pkts.append((Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                     IP(src=ROUTER_IP, dst=CLIENT_IP) /
                     ICMP(type=3, code=1) /
                     IP(src=CLIENT_IP, dst="10.0.0.99"),
                     _ts(t)))
    t_offset += 0.5

    # TTL Exceeded
    for i in range(2):
        t = t_offset + i * 0.1
        pkts.append((Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                     IP(src="172.16.0.1", dst=CLIENT_IP) /
                     ICMP(type=11, code=0) /
                     IP(src=CLIENT_IP, dst="192.168.99.1", ttl=1),
                     _ts(t)))
    t_offset += 0.5

    # === TCP section ===
    # Clean stream
    pkts.extend(_tcp_stream(sport=40000, start_time=t_offset, data_packets=5))
    t_offset += 2.0

    # Stream with retransmissions
    sport, dport = 40001, 80
    seq_c, seq_s = 5000, 6000
    t = t_offset
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_c += 1
    pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                 IP(src=SERVER_IP, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c, window=65535),
                 _ts(t)))
    t += 0.001; seq_s += 1
    pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                 IP(src=CLIENT_IP, dst=SERVER_IP) /
                 TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s, window=65535),
                 _ts(t)))
    t += 0.001
    for i in range(5):
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                     Raw(load=b"R" * 100), _ts(t)))
        t += 0.01
        # Retransmit
        pkts.append((Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
                     IP(src=CLIENT_IP, dst=SERVER_IP) /
                     TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s, window=65535) /
                     Raw(load=b"R" * 100), _ts(t)))
        t += 0.2
        seq_c += 100
        pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                     IP(src=SERVER_IP, dst=CLIENT_IP) /
                     TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c, window=65535),
                     _ts(t)))
        t += 0.001
    # RST teardown
    pkts.append((Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
                 IP(src=SERVER_IP, dst=CLIENT_IP) /
                 TCP(sport=dport, dport=sport, flags="R", seq=seq_s, window=0),
                 _ts(t)))
    t_offset = t + 1.0

    # === DNS section ===
    # Normal queries
    for i in range(10):
        t = t_offset + i * 0.1
        pkts.extend(_dns_pair(f"ok{i}.example.com", 0x8000 + i, t, 0.015))
    t_offset += 2.0

    # NXDOMAIN with DGA-like names
    random.seed(99)
    for i in range(5):
        t = t_offset + i * 0.15
        rand_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        pkts.extend(_dns_pair(f"{rand_name}.evil-c2.com", 0x8100 + i, t, 0.020, rcode=3))
    t_offset += 1.0

    # SERVFAIL
    for i in range(3):
        t = t_offset + i * 0.2
        pkts.extend(_dns_pair("broken.internal", 0x8200 + i, t, 0.025, rcode=2))
    t_offset += 1.0

    # Slow queries
    for i in range(3):
        t = t_offset + i * 0.5
        pkts.extend(_dns_pair(f"slow{i}.remote.com", 0x8300 + i, t, 0.500))
    t_offset += 2.0

    # TXT queries (tunneling indicator)
    for i in range(5):
        t = t_offset + i * 0.1
        pkts.extend(_dns_pair(f"data{i}.tunnel.evil.com", 0x8400 + i, t, 0.020, qtype=16))

    return _write_pcap("kitchen_sink.pcap", pkts,
                       "Multiple anomalies across all protocols")


# ---------------------------------------------------------------------------
# Main — generate all pcaps
# ---------------------------------------------------------------------------

GENERATORS = [
    ("healthy_small.pcap", gen_healthy_small),
    ("healthy_large.pcap", gen_healthy_large),
    ("arp_spoofing.pcap", gen_arp_spoofing),
    ("arp_unanswered.pcap", gen_arp_unanswered),
    ("icmp_unreachable_host.pcap", gen_icmp_unreachable_host),
    ("icmp_unreachable_port.pcap", gen_icmp_unreachable_port),
    ("icmp_pmtud_blackhole.pcap", gen_icmp_pmtud_blackhole),
    ("icmp_redirect.pcap", gen_icmp_redirect),
    ("icmp_ttl_exceeded.pcap", gen_icmp_ttl_exceeded),
    ("icmp_high_rtt.pcap", gen_icmp_high_rtt),
    ("tcp_retransmissions.pcap", gen_tcp_retransmissions),
    ("tcp_zero_window.pcap", gen_tcp_zero_window),
    ("tcp_rst_teardown.pcap", gen_tcp_rst_teardown),
    ("tcp_failed_handshake.pcap", gen_tcp_failed_handshake),
    ("tcp_dup_acks.pcap", gen_tcp_dup_acks),
    ("dns_nxdomain.pcap", gen_dns_nxdomain),
    ("dns_servfail.pcap", gen_dns_servfail),
    ("dns_slow_queries.pcap", gen_dns_slow_queries),
    ("dns_txt_heavy.pcap", gen_dns_txt_heavy),
    ("dns_unanswered.pcap", gen_dns_unanswered),
    ("mixed_host_down.pcap", gen_mixed_host_down),
    ("mixed_pmtud_tcp.pcap", gen_mixed_pmtud_tcp),
    ("kitchen_sink.pcap", gen_kitchen_sink),
]


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating {len(GENERATORS)} pcaps in {OUTPUT_DIR}/\n")

    results = []
    for name, gen_func in GENERATORS:
        path, count = gen_func()
        results.append((name, count))

    # Print summary table
    max_name = max(len(r[0]) for r in results)
    for name, count in results:
        print(f"  {name:<{max_name}}  {count:>5} packets")

    print(f"\nGenerated {len(results)} pcaps in {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
