#!/usr/bin/env python3
"""PCAP Forensic Engine — Extracts network metadata via tshark, builds a
compact Semantic JSON, and generates an AI-powered forensic report."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from dotenv import load_dotenv

# Load the .env file
load_dotenv()

# Now retrieve the key
api_key = os.getenv("GEMINI_API_KEY")

# TCP flag bitmasks
SYN = 0x0002
ACK = 0x0010
RST = 0x0004
FIN = 0x0001

# DNS RCODE names
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# ICMP type names for type_distribution
ICMP_TYPE_NAMES = {
    0: "echo_reply", 3: "dest_unreachable", 5: "redirect",
    8: "echo_request", 11: "time_exceeded",
}

# ICMP Destination Unreachable code meanings
ICMP_UNREACH_CODES = {
    0: "Network Unreachable", 1: "Host Unreachable",
    3: "Port Unreachable", 4: "Fragmentation Needed/DF Set",
    9: "Net Admin Prohibited", 10: "Host Admin Prohibited",
    13: "Communication Admin Prohibited",
}

# DNS query type names
DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

PROMPT_TEMPLATE = """\
You are an expert network forensic analyst with deep knowledge of TCP/IP
protocol internals, RFC specifications, and real-world failure modes. You
perform packet-level root cause analysis — not surface-level summarization.

You are given structured telemetry extracted from a packet capture file.
Identify root causes, correlate cross-protocol symptoms, and provide
specific, actionable remediation with exact CLI commands.

## Analysis Framework

When analyzing each protocol section, apply these diagnostic patterns:

### ARP Analysis
- IP-MAC conflicts (duplicate_ip_alerts): Multiple MACs claiming one IP = ARP
  spoofing/cache poisoning, or legitimate VRRP/HSRP failover. If two MACs are
  seen, check if one is a known virtual MAC prefix (00:00:5e:00 for VRRP,
  00:07:b4:00 for HSRP). If not, treat as CRITICAL spoofing alert.
- Unanswered ARP requests: Target host is down, wrong VLAN, or firewall
  blocking ARP at L2. If >5 unanswered for a specific IP, that host is
  unreachable at the data-link layer.
- Gratuitous ARP flood: >10 gratuitous ARPs in a short capture suggests
  VRRP/HSRP flapping, NIC teaming failover, or an ARP announcement storm.

### ICMP Analysis
- Destination Unreachable codes are critical diagnostic signals:
  - Code 0 (Network Unreachable): No route to destination network. The
    sending router's routing table is incomplete.
  - Code 1 (Host Unreachable): Router has a route to the network but the
    specific host doesn't respond to ARP — host is down or has wrong
    subnet mask.
  - Code 3 (Port Unreachable): UDP port is closed. The application is not
    listening. Common with DNS (53), SNMP (161), syslog (514) misconfig.
  - Code 4 (Fragmentation Needed, DF Set): PMTUD black hole. The path MTU
    is smaller than the packet size but the Don't Fragment bit prevents
    fragmentation. This causes large transfers to stall while small packets
    (pings, TCP handshakes) work fine — one of the most deceptive network
    failures. The ICMP message contains the next-hop MTU.
  - Code 9/10 (Admin Prohibited): Firewall is actively rejecting traffic
    with an ICMP response (not just silently dropping). This identifies the
    filtering device's IP.
  - Code 13 (Communication Admin Prohibited): Packet filter rule match.
- TTL Exceeded (Type 11): If from multiple different sources, likely
  traceroute. If the SAME source sends repeated TTL exceeded messages, this
  is a routing loop — packets are bouncing between routers, decrementing
  TTL each hop until expiry.
- ICMP Redirect (Type 5): A router is telling a host to use a different
  gateway. Can indicate suboptimal routing or a redirect-based MITM attack.
- Unmatched echo requests: If >50% unmatched, the target or path has a
  serious reachability problem. If <10% unmatched, likely transient loss.

### TCP Analysis
- Connection success rate < 90%: Server overload (SYN queue full, SYN
  cookies activated), firewall blocking, or the service is down. Check if
  RSTs come from the server IP (port closed/app crash) or from a different
  source IP (forged RSTs from firewall/IPS/ISP).
- Retransmission patterns:
  - Scattered across many streams = network-wide packet loss (congested
    link, bad cable/optic, duplex mismatch, CRC errors on interface)
  - Concentrated in 1-2 streams = endpoint-specific issue (slow
    application, kernel buffer exhaustion, CPU saturation on server)
  - Retransmissions with exponential backoff (successive deltas doubling:
    200ms->400ms->800ms) = RTO-based retransmission, meaning even Fast
    Retransmit failed — severe, sustained packet loss.
- Duplicate ACKs: 3+ duplicate ACKs trigger Fast Retransmit (RFC 5681).
  High dup ACK count relative to retransmission count means fast retransmit
  is working but packet loss is sustained. Low dup ACK count with high
  retransmissions means loss is so severe that not enough ACKs get through
  to trigger fast retransmit.
- Zero-window events: Receiver's TCP buffer is full because the application
  is not reading data fast enough. This is an APPLICATION bottleneck, not a
  network issue. The receiving application needs profiling (slow database
  queries, GC pauses, thread pool exhaustion). The sender is forced to wait
  (zero-window probe) until the application drains the buffer.
- Out-of-order packets: If correlated with a specific network path, suspect
  ECMP or LAG load balancing reordering packets across different physical
  paths with different latencies. If random across many streams, suspect
  network congestion causing variable queuing delay.
- RST origin analysis: RSTs from the server endpoint IP = port closed or
  application crashed. RSTs from an IP that is NEITHER the client nor server
  in the stream = an inline device (firewall, IDS/IPS, or ISP middlebox)
  is forging TCP RSTs to tear down the connection.
- ACK RTT distribution: If p95/median ratio > 10, suspect bufferbloat in
  an intermediate device (router/switch with oversized buffers absorbing
  bursts but adding massive queuing delay to the tail).

### DNS Analysis
- NXDOMAIN patterns:
  - Random-looking names (e.g., "xk3f9a2.example.com") returning NXDOMAIN
    = DGA malware (Domain Generation Algorithm) trying to reach C2 servers.
    This is a CRITICAL security finding.
  - Misspelled real domains (e.g., "gogle.com") = typo or misconfigured
    service discovery.
  - Sequential subdomains = zone enumeration/reconnaissance.
- SERVFAIL domains: The DNS server cannot resolve these — authoritative
  server is down, DNSSEC validation failed, or the zone is misconfigured.
  Critical if it affects production service hostnames.
- Query type distribution:
  - TXT queries >20% of total = potential DNS tunneling for data
    exfiltration (tools: iodine, dnscat2, dns2tcp). CRITICAL security
    finding.
  - High PTR query ratio = reverse DNS lookups from a scanner or IDS.
  - ANY queries = DNS amplification attack preparation.
- Unanswered queries >5%: DNS server is overloaded, unreachable, or
  rate-limiting. This degrades all name-dependent services.
- Latency outliers >200ms: Query is traversing multiple forwarders or the
  authoritative server is distant/overloaded.
- Truncated responses: Response too large for UDP. Client should retry
  over TCP. If truncation count is high, check EDNS0 buffer size
  configuration on the resolver.
- Unexpected DNS servers: If dns_servers_queried contains IPs that are
  not the organization's designated resolvers, this may indicate DNS
  hijacking, DHCP-injected rogue DNS, or a misconfigured /etc/resolv.conf.

### Cross-Protocol Correlation
Apply these multi-protocol diagnostic patterns when evidence from multiple
protocol sections points to the same root cause:
- ARP unanswered for IP X + ICMP Host Unreachable (Code 1) for IP X =
  host X is confirmed down or disconnected from the L2 segment.
- ICMP Fragmentation Needed (Code 4) + TCP retransmissions concentrated
  on streams with large tcp.len = PMTUD black hole. The path has a
  smaller MTU than the endpoints expect, and the DF bit prevents
  fragmentation, so large segments are silently dropped.
- DNS NXDOMAIN for domain Y + TCP SYN to resolved IP with RST response =
  application using stale DNS cache after domain was removed.
- High DNS latency to server IP Z + TCP retransmissions to same IP Z =
  the DNS server itself has connectivity or performance issues, not just
  DNS-layer problems.
- ICMP TTL Exceeded from same router IP + high TCP retransmissions =
  routing loop is causing packet loss as packets exhaust their TTL
  bouncing between routers.

## Output Format

Produce a forensic report in Markdown with exactly these sections:

## Executive Summary
2-4 sentences stating the most critical finding and its likely root cause.
Be specific — name the IPs, ports, and protocols involved. Prioritize by
severity: security issues > connectivity failures > performance degradation
> informational. If no issues found, state the capture appears healthy with
specific evidence (e.g., "100% TCP handshake success rate, 0 retransmissions,
all 10 DNS queries answered within 15ms median latency").

## Anomaly Table
A Markdown table with columns: Severity | Protocol | Issue | Detail | Frame(s)
Severity levels:
  - CRITICAL: Active security threat (ARP spoofing, DNS tunneling indicators)
  - HIGH: Service-impacting (host unreachable, connection failures, zero-window)
  - MEDIUM: Performance degradation (retransmissions, elevated latency)
  - LOW: Worth monitoring (occasional retransmissions, minor latency spikes)
  - INFO: Notable but benign observations
Use specific frame numbers, IPs, and port numbers from the data.
If no anomalies: "INFO | — | No anomalies detected | All protocols operating
within normal parameters | —"

## Root Cause Analysis
For each HIGH or CRITICAL finding, provide a 2-3 sentence technical
explanation: what protocol behavior indicates the problem, what the expected
behavior is (cite the RFC if relevant), and how it correlates with other
findings in the capture. Skip this section entirely if no HIGH/CRITICAL findings.

## Remediation
For each finding, provide specific remediation with exact CLI commands.
Specify which host/device each command should run on.

Examples of the specificity expected:
- ARP spoofing: "On switch: `ip arp inspection vlan <id>`. On host:
  `arp -d 10.0.0.5 && ip neigh flush dev eth0`"
- PMTUD black hole: "On sender: `ping -M do -s 1400 <dst>` to find working
  MTU. Then: `ip link set dev eth0 mtu <value>` or
  `iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`"
- TCP retransmissions: "On server: `ethtool eth0 | grep -i duplex` to check
  duplex. `netstat -s | grep retrans` for kernel retransmit stats.
  `tc -s qdisc show dev eth0` for queue drops."
- Zero-window: "On receiver: `ss -tnp dst <ip>` to identify the process.
  Check application logs for slow queries or GC pauses."
- DNS SERVFAIL: "Test: `dig +trace example.com @<server>`. Check zone:
  `named-checkzone example.com /etc/bind/zones/example.com.zone`.
  Restart: `systemctl restart named`"
- DNS tunneling: "Block: `iptables -A OUTPUT -p udp --dport 53 -m string
  --algo bm --hex-string '|<pattern>|' -j DROP`. Investigate the source
  host for malware."

If no issues: "No action required — capture indicates healthy network
operation."

## Rules
- Every claim must be supported by data in the JSON. Do not fabricate
  frame numbers, IPs, or statistics.
- Do not speculate beyond what the data supports. When data is insufficient,
  state what additional capture or data would be needed.
- Correlate across protocols — the most valuable insights come from
  connecting symptoms across layers.

--- BEGIN SEMANTIC JSON ---
{semantic_json}
--- END SEMANTIC JSON ---"""

COMPARE_PROMPT_TEMPLATE = """\
You are an expert network forensic analyst performing a comparative analysis
of two packet captures taken at different times from the same network segment.
Your goal is to identify what changed between the two captures and determine
whether network health improved, degraded, or remained stable.

You are given two sets of structured telemetry labelled "Capture A" (baseline)
and "Capture B" (current). Identify regressions, improvements, new issues,
and resolved issues by comparing the metrics and anomalies across captures.

## Comparison Framework

For each protocol present in either capture, compare these dimensions:

### ARP Comparison
- New IP-MAC conflicts in B that weren't in A = new spoofing activity
- IP-MAC conflicts in A resolved in B = spoofing stopped or remediated
- Change in unanswered ARP count = host availability change
- New gratuitous ARP activity = possible failover event

### ICMP Comparison
- New Destination Unreachable types/codes in B = new connectivity failures
- RTT regression (B median/p95 significantly higher than A) = path degradation
- New TTL Exceeded sources = new routing loop
- Resolved unreachable entries = connectivity restored

### TCP Comparison
- Retransmission rate change (retransmissions/total packets) — not raw counts
- Handshake success rate change
- New zero-window events = new application bottleneck
- New streams with issues that were healthy in A
- RST teardown rate change

### DNS Comparison
- New NXDOMAIN domains in B = new misconfiguration or DGA activity
- Latency regression (B median/p95 vs A)
- New SERVFAIL domains = new zone failures
- Change in query type distribution = behavioral shift
- New DNS servers queried = resolver configuration change

### Cross-Capture Correlation
- Same host appearing in both ARP unanswered (A) and ICMP unreachable (B)
  = persistent host-down issue
- Issue in A's TCP retransmissions resolved in B + new ICMP Frag Needed in B
  = MTU fix applied but with side effects
- DNS latency regression in B + same DNS server showing TCP retransmissions
  in B = DNS server degradation

## Output Format

Produce a comparative forensic report in Markdown with exactly these sections:

## Executive Summary
2-4 sentences stating the overall trajectory (improved/degraded/stable) with
the most significant change. Name specific IPs, protocols, and metrics.

## Change Summary Table
A Markdown table: Protocol | Metric | Capture A | Capture B | Delta | Assessment
Assessment values: REGRESSION, IMPROVEMENT, STABLE, NEW ISSUE, RESOLVED
Include key metrics for every protocol present in either capture.

## New Issues (Capture B only)
Issues present in B but not in A. Use the same severity classification
(CRITICAL/HIGH/MEDIUM/LOW/INFO) and format as the single-capture Anomaly
Table: Severity | Protocol | Issue | Detail | Frame(s)
If none: "No new issues detected."

## Resolved Issues (Capture A only)
Issues that were present in A but are absent in B. Same table format.
If none: "No issues from Capture A were resolved."

## Regressions
For each metric that worsened significantly between A and B, provide a 2-3
sentence technical explanation of what the change indicates and possible
root causes. Skip if no regressions.

## Remediation
Specific CLI commands for each new issue or regression, with the same
specificity as the single-capture report. If no issues: "No action required."

## Rules
- Compare RATES and RATIOS, not raw counts (captures may have different
  durations and packet volumes). Use avg_packets_per_second and
  duration_seconds to normalize.
- Every claim must be supported by data from one or both captures.
- Do not speculate beyond what the data supports.
- A metric changing by <10% is STABLE. 10-50% is noteworthy. >50% is
  significant. >200% is critical.

--- BEGIN CAPTURE A (BASELINE) ---
{semantic_json_a}
--- END CAPTURE A ---

--- BEGIN CAPTURE B (CURRENT) ---
{semantic_json_b}
--- END CAPTURE B ---"""


# ---------------------------------------------------------------------------
# Helpers — parsing tshark's tab-separated output
# ---------------------------------------------------------------------------

def _parse_optional_int(value: str) -> int | None:
    """Parse a tshark field to int, returning None for empty/missing fields.
    Takes the first value if the field is comma-separated (multi-value)."""
    value = value.strip()
    if not value:
        return None
    return int(value.split(",")[0], 0)


def _parse_optional_float(value: str) -> float | None:
    """Parse a tshark field to float, returning None for empty/missing fields."""
    value = value.strip()
    if not value:
        return None
    return float(value.split(",")[0])


def _parse_str(value: str) -> str:
    """Parse a tshark string field. Takes first value if comma-separated."""
    return value.split(",")[0].strip() if value else ""


def _parse_bool_present(value: str) -> bool:
    """Parse a tshark 'present when true' field to bool."""
    return bool(value.strip())


def _parse_bool_flag(value: str) -> bool:
    """Parse a tshark boolean flag field (True/False or 1/0) to bool."""
    v = value.strip().split(",")[0]
    return v in ("1", "True")


# ---------------------------------------------------------------------------
# Stage 1 — Input Validation
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PCAP Forensic Engine — AI-powered network forensic analysis")
    parser.add_argument("pcap", help="Path to .pcap/.pcapng file")
    parser.add_argument("--semantic-dir",
        help="Output directory for semantic JSON (default: same as input)")
    parser.add_argument("--report-dir",
        help="Output directory for forensic report (default: same as input)")
    parser.add_argument("--compare", metavar="PCAP2",
        help="Second pcap for comparative analysis (produces diff report)")
    return parser.parse_args()


def validate_input(pcap_arg: str) -> Path:
    pcap_path = Path(pcap_arg)

    if not pcap_path.exists():
        print(f"Error: File not found: {pcap_path}")
        sys.exit(1)

    if not pcap_path.is_file() or not os.access(pcap_path, os.R_OK):
        print(f"Error: File is not readable: {pcap_path}")
        sys.exit(1)

    if pcap_path.suffix.lower() not in (".pcap", ".pcapng"):
        print(f"Error: Unsupported file extension '{pcap_path.suffix}'. "
              "Expected .pcap or .pcapng")
        sys.exit(1)

    if not shutil.which("tshark"):
        print("Error: tshark is not installed or not on PATH.")
        print("  Install Wireshark/tshark:")
        print("    macOS:   brew install wireshark")
        print("    Ubuntu:  sudo apt install tshark")
        print("    Windows: https://www.wireshark.org/download.html")
        sys.exit(1)

    if not os.environ.get("GEMINI_API_KEY"):
        print("Error: Set GEMINI_API_KEY environment variable.")
        sys.exit(1)

    return pcap_path


# ---------------------------------------------------------------------------
# Stage 2 — Protocol Extraction (tshark)
# ---------------------------------------------------------------------------

def run_tshark(pcap_path: Path, fields: list[str],
               display_filter: str = "") -> list[list[str]]:
    """Run a tshark command and return rows of tab-separated field values.
    Uses list args — never shell=True — to prevent command injection."""
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields"]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "separator=\t", "-E", "header=n"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed: {result.stderr.strip()}")

    rows = []
    for line in result.stdout.strip().split("\n"):
        if line:
            rows.append(line.split("\t"))
    return rows


def extract_capture_summary(pcap_path: Path) -> dict:
    """Stream every packet's frame number and timestamp from tshark line by
    line.  Only three values are kept in memory regardless of pcap size."""
    cmd = [
        "tshark", "-r", str(pcap_path), "-T", "fields",
        "-e", "frame.number", "-e", "frame.time_epoch",
        "-E", "separator=\t", "-E", "header=n",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)

    count = 0
    first_ts = 0.0
    last_ts = 0.0

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            ts = float(parts[1])
            if count == 0:
                first_ts = ts
            last_ts = ts
            count += 1

    proc.wait()
    if proc.returncode != 0:
        stderr_text = proc.stderr.read()
        raise RuntimeError(f"tshark failed: {stderr_text.strip()}")

    duration = last_ts - first_ts if count > 1 else 0.0
    return {
        "file": pcap_path.name,
        "total_packets": count,
        "duration_seconds": round(duration, 3),
    }


def extract_arp(pcap_path: Path) -> list[dict]:
    fields = [
        "frame.number", "frame.time_epoch", "arp.opcode",
        "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    ]
    packets = []
    for row in run_tshark(pcap_path, fields, "arp"):
        if len(row) < 6:
            continue
        packets.append({
            "frame": int(row[0]),
            "timestamp": float(row[1]),
            "opcode": _parse_optional_int(row[2]),
            "src_mac": _parse_str(row[3]),
            "src_ip": _parse_str(row[4]),
            "dst_ip": _parse_str(row[5]),
        })
    return packets


def extract_icmp(pcap_path: Path) -> list[dict]:
    fields = [
        "frame.number", "frame.time_epoch", "icmp.type", "icmp.code",
        "icmp.seq", "icmp.resp_in", "frame.time_delta",
        "ip.src", "ip.dst",
    ]
    packets = []
    for row in run_tshark(pcap_path, fields, "icmp"):
        if len(row) < 9:
            continue
        packets.append({
            "frame": int(row[0]),
            "timestamp": float(row[1]),
            "type": _parse_optional_int(row[2]),
            "code": _parse_optional_int(row[3]),
            "seq": _parse_optional_int(row[4]),
            "resp_in": _parse_optional_int(row[5]),
            "time_delta": _parse_optional_float(row[6]),
            "src_ip": _parse_str(row[7]),
            "dst_ip": _parse_str(row[8]),
        })
    return packets


def extract_tcp(pcap_path: Path) -> list[dict]:
    fields = [
        "frame.number", "frame.time_epoch", "tcp.stream",
        "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
        "tcp.flags", "tcp.analysis.retransmission",
        "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
        "tcp.analysis.zero_window", "tcp.analysis.ack_rtt",
        "tcp.len", "tcp.window_size_value", "tcp.time_delta",
    ]
    packets = []
    for row in run_tshark(pcap_path, fields, "tcp"):
        if len(row) < 16:
            continue
        flags_str = _parse_str(row[7])
        packets.append({
            "frame": int(row[0]),
            "timestamp": float(row[1]),
            "stream": _parse_optional_int(row[2]),
            "src_ip": _parse_str(row[3]),
            "src_port": _parse_optional_int(row[4]),
            "dst_ip": _parse_str(row[5]),
            "dst_port": _parse_optional_int(row[6]),
            "flags": int(flags_str, 16) if flags_str else 0,
            "is_retransmission": _parse_bool_present(row[8]),
            "is_duplicate_ack": _parse_bool_present(row[9]),
            "is_out_of_order": _parse_bool_present(row[10]),
            "is_zero_window": _parse_bool_present(row[11]),
            "ack_rtt": _parse_optional_float(row[12]),
            "tcp_len": _parse_optional_int(row[13]),
            "window_size": _parse_optional_int(row[14]),
            "time_delta": _parse_optional_float(row[15]),
        })
    return packets


def extract_dns(pcap_path: Path) -> list[dict]:
    fields = [
        "frame.number", "frame.time_epoch", "dns.id",
        "dns.flags.response", "dns.qry.name", "dns.qry.type",
        "dns.flags.rcode", "dns.time",
        "dns.count.answers", "dns.flags.truncated", "ip.dst",
    ]
    packets = []
    for row in run_tshark(pcap_path, fields, "dns"):
        if len(row) < 11:
            continue
        # dns.flags.response may be "True"/"False" or "1"/"0"
        resp_raw = row[3].strip().split(",")[0]
        is_response = 1 if resp_raw in ("1", "True") else 0
        packets.append({
            "frame": int(row[0]),
            "timestamp": float(row[1]),
            "dns_id": _parse_optional_int(row[2]),
            "is_response": is_response,
            "qry_name": _parse_str(row[4]),
            "qry_type": _parse_optional_int(row[5]),
            "rcode": _parse_optional_int(row[6]),
            "dns_time": _parse_optional_float(row[7]),
            "answer_count": _parse_optional_int(row[8]),
            "is_truncated": _parse_bool_flag(row[9]),
            "dst_ip": _parse_str(row[10]),
        })
    return packets


def extract_all(pcap_path: Path) -> dict:
    summary = extract_capture_summary(pcap_path)

    arp = extract_arp(pcap_path)
    print(f"      ARP:  {len(arp):,} packets")

    icmp = extract_icmp(pcap_path)
    print(f"      ICMP: {len(icmp):,} packets")

    tcp = extract_tcp(pcap_path)
    print(f"      TCP:  {len(tcp):,} packets")

    dns = extract_dns(pcap_path)
    print(f"      DNS:  {len(dns):,} packets")

    return {
        "summary": summary,
        "arp": arp,
        "icmp": icmp,
        "tcp": tcp,
        "dns": dns,
    }


# ---------------------------------------------------------------------------
# Stage 3 — Semantic Reduction
# ---------------------------------------------------------------------------

def compute_stats(values: list[float]) -> dict:
    if not values:
        return {"min": 0, "median": 0, "p95": 0, "max": 0}
    s = sorted(values)
    n = len(s)
    return {
        "min": round(s[0], 2),
        "median": round(statistics.median(s), 2),
        "p95": round(s[int(n * 0.95)], 2),
        "max": round(s[-1], 2),
    }


def reduce_arp(raw: list[dict]) -> dict:
    total_requests = 0
    total_replies = 0
    gratuitous_count = 0
    replied_ips = set()
    request_targets = defaultdict(int)

    # IP-MAC conflict detection: ip -> {mac: first_frame}
    ip_to_macs: dict[str, dict[str, int]] = defaultdict(dict)

    for pkt in raw:
        opcode = pkt.get("opcode")
        src_ip = pkt.get("src_ip", "")
        dst_ip = pkt.get("dst_ip", "")
        src_mac = pkt.get("src_mac", "")

        # Track IP->MAC mappings from src_ip -> src_mac
        if src_ip and src_mac:
            if src_mac not in ip_to_macs[src_ip]:
                ip_to_macs[src_ip][src_mac] = pkt["frame"]

        if opcode == 1:
            total_requests += 1
            if src_ip and dst_ip and src_ip == dst_ip:
                gratuitous_count += 1
            else:
                request_targets[dst_ip] += 1
        elif opcode == 2:
            total_replies += 1
            replied_ips.add(src_ip)

    unanswered = [
        {"ip": ip, "count": count}
        for ip, count in sorted(request_targets.items())
        if ip not in replied_ips
    ]

    # Build duplicate_ip_alerts for IPs with >1 MAC
    duplicate_ip_alerts = []
    for ip, mac_frames in sorted(ip_to_macs.items()):
        if len(mac_frames) > 1:
            duplicate_ip_alerts.append({
                "ip": ip,
                "macs": sorted(mac_frames.keys()),
                "sample_frames": [mac_frames[m] for m in sorted(mac_frames.keys())],
            })

    result = {
        "total_requests": total_requests,
        "total_replies": total_replies,
        "unanswered_requests": unanswered,
        "gratuitous_arp_count": gratuitous_count,
    }
    if duplicate_ip_alerts:
        result["duplicate_ip_alerts"] = duplicate_ip_alerts
    return result


def reduce_icmp(raw: list[dict]) -> dict:
    # Build frame_number -> timestamp lookup for RTT calculation
    ts_map = {pkt["frame"]: pkt["timestamp"] for pkt in raw}

    # Build seq -> reply_frame lookup as fallback when icmp.resp_in is empty
    reply_by_seq: dict[int, int] = {}
    for pkt in raw:
        if pkt.get("type") == 0 and pkt.get("seq") is not None:
            reply_by_seq.setdefault(pkt["seq"], pkt["frame"])

    matched = 0
    unmatched = 0
    rtt_entries = []  # (rtt_ms, seq, frame)

    for pkt in raw:
        if pkt.get("type") != 8:  # Only Echo Requests
            continue
        resp_frame = pkt.get("resp_in")
        # Fallback: match by sequence number if resp_in not populated
        if resp_frame is None:
            resp_frame = reply_by_seq.get(pkt.get("seq"))
        if resp_frame is not None and resp_frame in ts_map:
            rtt_ms = round((ts_map[resp_frame] - pkt["timestamp"]) * 1000, 2)
            rtt_entries.append((rtt_ms, pkt.get("seq"), pkt["frame"]))
            matched += 1
        else:
            unmatched += 1

    rtts = [e[0] for e in rtt_entries]
    rtt_stats = compute_stats(rtts)

    anomalies = []
    if rtt_stats["median"] > 0:
        threshold = rtt_stats["median"] * 2
        for rtt_ms, seq, frame in rtt_entries:
            if rtt_ms > threshold:
                anomalies.append({"seq": seq, "rtt_ms": rtt_ms, "frame": frame})

    result = {
        "echo_pairs_matched": matched,
        "echo_unmatched": unmatched,
        "rtt_ms": rtt_stats,
        "anomalies": anomalies,
    }

    # Type distribution
    type_counts: dict[str, int] = defaultdict(int)
    for pkt in raw:
        t = pkt.get("type")
        if t is not None:
            name = ICMP_TYPE_NAMES.get(t, f"type_{t}")
            type_counts[name] += 1
    if type_counts:
        result["type_distribution"] = dict(type_counts)

    # Destination Unreachable details (Type 3)
    unreach_groups: dict[tuple, dict] = {}
    for pkt in raw:
        if pkt.get("type") != 3:
            continue
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        code = pkt.get("code", 0)
        key = (src, dst, code)
        if key not in unreach_groups:
            unreach_groups[key] = {
                "src": src, "dst": dst, "code": code,
                "code_meaning": ICMP_UNREACH_CODES.get(code, f"Code {code}"),
                "count": 0, "sample_frame": pkt["frame"],
            }
        unreach_groups[key]["count"] += 1
    if unreach_groups:
        result["unreachable_details"] = list(unreach_groups.values())

    # Redirect details (Type 5)
    redirect_groups: dict[str, dict] = {}
    for pkt in raw:
        if pkt.get("type") != 5:
            continue
        src = pkt.get("src_ip", "")
        if src not in redirect_groups:
            redirect_groups[src] = {
                "src": src, "gateway": pkt.get("dst_ip", ""),
                "count": 0, "sample_frame": pkt["frame"],
            }
        redirect_groups[src]["count"] += 1
    if redirect_groups:
        result["redirect_details"] = list(redirect_groups.values())

    # TTL Exceeded sources (Type 11)
    ttl_groups: dict[str, dict] = {}
    for pkt in raw:
        if pkt.get("type") != 11:
            continue
        src = pkt.get("src_ip", "")
        if src not in ttl_groups:
            ttl_groups[src] = {
                "src": src, "count": 0, "sample_frame": pkt["frame"],
            }
        ttl_groups[src]["count"] += 1
    if ttl_groups:
        result["ttl_exceeded_sources"] = list(ttl_groups.values())

    return result


def reduce_tcp(raw: list[dict]) -> dict:
    streams = defaultdict(list)
    for pkt in raw:
        stream_id = pkt.get("stream")
        if stream_id is not None:
            streams[stream_id].append(pkt)

    retransmissions_total = 0
    rst_count_total = 0
    duplicate_ack_total = 0
    out_of_order_total = 0
    zero_window_total = 0
    all_deltas = []
    per_stream = {}

    # Connection lifecycle counters
    syn_sent = 0
    syn_ack_received = 0
    rst_teardown_streams = set()
    fin_teardown_streams = set()

    # First pass: per-stream stats
    for stream_id, pkts in streams.items():
        retrans = 0
        rst_count = 0
        dup_ack = 0
        ooo = 0
        zero_win = 0
        notable_frames_set = set()
        deltas = []
        ack_rtts = []
        has_syn = False
        has_syn_ack = False
        has_post_handshake_ack = False

        for pkt in pkts:
            flags = pkt.get("flags", 0)

            # Connection lifecycle tracking
            if (flags & SYN) and not (flags & ACK):
                has_syn = True
                syn_sent += 1
            if (flags & SYN) and (flags & ACK):
                has_syn_ack = True
                syn_ack_received += 1
            if (flags & ACK) and not (flags & SYN) and has_syn_ack:
                has_post_handshake_ack = True

            if flags & RST:
                rst_count += 1
                rst_teardown_streams.add(stream_id)
                notable_frames_set.add(pkt["frame"])
            if flags & FIN:
                fin_teardown_streams.add(stream_id)

            if pkt.get("is_retransmission"):
                retrans += 1
                notable_frames_set.add(pkt["frame"])
            if pkt.get("is_duplicate_ack"):
                dup_ack += 1
                notable_frames_set.add(pkt["frame"])
            if pkt.get("is_out_of_order"):
                ooo += 1
                notable_frames_set.add(pkt["frame"])
            if pkt.get("is_zero_window"):
                zero_win += 1
                notable_frames_set.add(pkt["frame"])

            delta = pkt.get("time_delta")
            if delta is not None:
                delta_ms = round(delta * 1000, 2)
                deltas.append(delta_ms)
                all_deltas.append(delta_ms)

            art = pkt.get("ack_rtt")
            if art is not None:
                ack_rtts.append(round(art * 1000, 2))

        retransmissions_total += retrans
        rst_count_total += rst_count
        duplicate_ack_total += dup_ack
        out_of_order_total += ooo
        zero_window_total += zero_win

        handshake_complete = has_syn and has_syn_ack and has_post_handshake_ack

        per_stream[stream_id] = {
            "first": pkts[0],
            "retrans": retrans,
            "dup_ack": dup_ack,
            "ooo": ooo,
            "zero_win": zero_win,
            "rst_present": rst_count > 0,
            "notable_frames": sorted(notable_frames_set)[:5],
            "delta_stats": compute_stats(deltas),
            "ack_rtt_stats": compute_stats(ack_rtts),
            "handshake_complete": handshake_complete,
        }

    overall_median = statistics.median(all_deltas) if all_deltas else 0

    # Compute handshake stats
    handshakes_completed = sum(
        1 for d in per_stream.values() if d["handshake_complete"]
    )
    handshake_success_pct = round(
        handshakes_completed / syn_sent * 100, 1
    ) if syn_sent > 0 else 0.0

    # Second pass: filter streams with issues
    streams_with_issues = []
    for stream_id, data in per_stream.items():
        has_retrans = data["retrans"] > 0
        has_dup_ack = data["dup_ack"] > 0
        has_ooo = data["ooo"] > 0
        has_zero_win = data["zero_win"] > 0
        has_rst = data["rst_present"]
        has_high_delta = (
            data["delta_stats"]["p95"] > overall_median * 2
            if overall_median > 0 else False
        )
        if not (has_retrans or has_dup_ack or has_ooo or has_zero_win
                or has_rst or has_high_delta):
            continue

        first = data["first"]
        streams_with_issues.append({
            "stream_id": stream_id,
            "src": f"{first.get('src_ip', '')}:{first.get('src_port', '')}",
            "dst": f"{first.get('dst_ip', '')}:{first.get('dst_port', '')}",
            "retransmissions": data["retrans"],
            "duplicate_acks": data["dup_ack"],
            "out_of_order": data["ooo"],
            "zero_window_events": data["zero_win"],
            "rst": data["rst_present"],
            "ack_rtt_ms": data["ack_rtt_stats"],
            "delta_ms": data["delta_stats"],
            "sample_frames": data["notable_frames"],
        })

    return {
        "streams_total": len(streams),
        "retransmissions_total": retransmissions_total,
        "rst_count": rst_count_total,
        "duplicate_ack_total": duplicate_ack_total,
        "out_of_order_total": out_of_order_total,
        "zero_window_total": zero_window_total,
        "connection_stats": {
            "syn_sent": syn_sent,
            "syn_ack_received": syn_ack_received,
            "handshakes_completed": handshakes_completed,
            "handshake_success_rate_pct": handshake_success_pct,
            "rst_teardowns": len(rst_teardown_streams),
            "fin_teardowns": len(fin_teardown_streams),
        },
        "streams_with_issues": streams_with_issues,
    }


def reduce_dns(raw: list[dict]) -> dict:
    queries = []
    responses = []
    for pkt in raw:
        if pkt.get("is_response") == 1:
            responses.append(pkt)
        else:
            queries.append(pkt)

    # Unanswered queries: query dns_id with no matching response dns_id
    response_ids = {
        pkt["dns_id"] for pkt in responses if pkt.get("dns_id") is not None
    }
    unanswered = sum(
        1 for q in queries
        if q.get("dns_id") is not None and q["dns_id"] not in response_ids
    )

    # RCODE distribution
    rcode_dist = defaultdict(int)
    for pkt in responses:
        rcode = pkt.get("rcode")
        if rcode is not None:
            rcode_dist[RCODE_NAMES.get(rcode, f"RCODE_{rcode}")] += 1

    # Latency stats — dns.time is in seconds, convert to ms
    latency_entries = []
    for pkt in responses:
        dns_time = pkt.get("dns_time")
        if dns_time is not None:
            latency_ms = round(dns_time * 1000, 2)
            latency_entries.append({
                "latency_ms": latency_ms,
                "name": pkt.get("qry_name", ""),
                "frame": pkt["frame"],
            })

    latencies = [e["latency_ms"] for e in latency_entries]
    latency_stats = compute_stats(latencies)

    # Slow query anomalies: latency > 2x median
    slow_queries = []
    if latency_stats["median"] > 0:
        threshold = latency_stats["median"] * 2
        for entry in latency_entries:
            if entry["latency_ms"] > threshold:
                slow_queries.append(entry)

    result = {
        "queries_total": len(queries),
        "responses_total": len(responses),
        "unanswered_queries": unanswered,
        "rcode_distribution": dict(rcode_dist),
        "latency_ms": latency_stats,
        "slow_queries": slow_queries,
    }

    # Query type distribution
    qtype_counts: dict[str, int] = defaultdict(int)
    for pkt in queries:
        qt = pkt.get("qry_type")
        if qt is not None:
            name = DNS_QTYPE_NAMES.get(qt, f"TYPE_{qt}")
            qtype_counts[name] += 1
    if qtype_counts:
        result["query_type_distribution"] = dict(qtype_counts)

    # NXDOMAIN domains (rcode=3) — top 10 by count
    nxdomain_groups: dict[str, dict] = {}
    for pkt in responses:
        if pkt.get("rcode") != 3:
            continue
        name = pkt.get("qry_name", "")
        if name not in nxdomain_groups:
            nxdomain_groups[name] = {
                "name": name, "count": 0, "sample_frame": pkt["frame"],
            }
        nxdomain_groups[name]["count"] += 1
    if nxdomain_groups:
        result["nxdomain_domains"] = sorted(
            nxdomain_groups.values(), key=lambda x: x["count"], reverse=True
        )[:10]

    # SERVFAIL domains (rcode=2) — top 10 by count
    servfail_groups: dict[str, dict] = {}
    for pkt in responses:
        if pkt.get("rcode") != 2:
            continue
        name = pkt.get("qry_name", "")
        if name not in servfail_groups:
            servfail_groups[name] = {
                "name": name, "count": 0, "sample_frame": pkt["frame"],
            }
        servfail_groups[name]["count"] += 1
    if servfail_groups:
        result["servfail_domains"] = sorted(
            servfail_groups.values(), key=lambda x: x["count"], reverse=True
        )[:10]

    # Top queried domains — top 10 by count
    domain_counts: dict[str, int] = defaultdict(int)
    for pkt in queries:
        name = pkt.get("qry_name", "")
        if name:
            domain_counts[name] += 1
    if domain_counts:
        result["top_queried_domains"] = [
            {"name": name, "count": count}
            for name, count in sorted(
                domain_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]

    # DNS servers queried (unique dst_ip from queries)
    dns_servers = set()
    for pkt in queries:
        dst = pkt.get("dst_ip", "")
        if dst:
            dns_servers.add(dst)
    if dns_servers:
        result["dns_servers_queried"] = sorted(dns_servers)

    # Truncated responses
    truncated = sum(1 for pkt in responses if pkt.get("is_truncated"))
    result["truncated_responses"] = truncated

    return result


def reduce_to_semantic(raw_data: dict) -> dict:
    summary = raw_data["summary"]
    protocols_present = []

    duration = summary["duration_seconds"]
    total = summary["total_packets"]
    avg_pps = round(total / duration, 1) if duration > 0 else 0.0

    semantic = {
        "capture_summary": {
            "file": summary["file"],
            "total_packets": total,
            "duration_seconds": duration,
            "avg_packets_per_second": avg_pps,
        }
    }

    if raw_data["arp"]:
        protocols_present.append("ARP")
        semantic["arp"] = reduce_arp(raw_data["arp"])

    if raw_data["icmp"]:
        protocols_present.append("ICMP")
        semantic["icmp"] = reduce_icmp(raw_data["icmp"])

    if raw_data["tcp"]:
        protocols_present.append("TCP")
        semantic["tcp"] = reduce_tcp(raw_data["tcp"])

    if raw_data["dns"]:
        protocols_present.append("DNS")
        semantic["dns"] = reduce_dns(raw_data["dns"])

    semantic["capture_summary"]["protocols_present"] = protocols_present
    return semantic


def save_semantic_json(semantic: dict, pcap_path: Path,
                       output_dir: Path | None = None) -> Path:
    base_dir = output_dir if output_dir else pcap_path.parent
    base_dir.mkdir(parents=True, exist_ok=True)
    out_path = base_dir / f"{pcap_path.stem}_semantic.json"
    out_path.write_text(json.dumps(semantic, indent=2) + "\n", encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Stage 4 — AI Diagnosis + Report Generation
# ---------------------------------------------------------------------------

def build_prompt(semantic: dict) -> str:
    return PROMPT_TEMPLATE.format(semantic_json=json.dumps(semantic, indent=2))


def build_compare_prompt(semantic_a: dict, semantic_b: dict) -> str:
    return COMPARE_PROMPT_TEMPLATE.format(
        semantic_json_a=json.dumps(semantic_a, indent=2),
        semantic_json_b=json.dumps(semantic_b, indent=2),
    )


def call_gemini(prompt: str) -> str:
    try:
        from google import genai
    except ImportError:
        raise RuntimeError(
            "google-genai package is not installed. "
            "Run: pip install google-genai"
        )

    client = genai.Client(api_key=api_key)

    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
    except Exception as e:
        error_msg = str(e)
        if api_key and api_key in error_msg:
            error_msg = error_msg.replace(api_key, "***")
        raise RuntimeError(f"Gemini API error: {error_msg}")

    if not response.text:
        raise RuntimeError(
            "Gemini returned an empty response (possible safety block). "
            "The semantic JSON has been saved — you can inspect it directly."
        )
    return response.text


def generate_report(semantic: dict) -> str:
    prompt = build_prompt(semantic)
    return call_gemini(prompt)


def save_report(report_text: str, pcap_path: Path,
                output_dir: Path | None = None) -> Path:
    base_dir = output_dir if output_dir else pcap_path.parent
    base_dir.mkdir(parents=True, exist_ok=True)
    out_path = base_dir / f"{pcap_path.stem}_forensic_report.md"
    out_path.write_text(report_text, encoding="utf-8")
    return out_path


def save_comparison_report(report_text: str, pcap_a: Path, pcap_b: Path,
                           output_dir: Path | None = None) -> Path:
    base_dir = output_dir if output_dir else pcap_a.parent
    base_dir.mkdir(parents=True, exist_ok=True)
    out_path = base_dir / f"{pcap_a.stem}_vs_{pcap_b.stem}_comparison.md"
    out_path.write_text(report_text, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        args = parse_args()

        if args.compare:
            # --- Compare mode ---
            print("[1/5] Validating inputs...")
            pcap_a = validate_input(args.pcap)
            pcap_b = validate_input(args.compare)
            semantic_dir = Path(args.semantic_dir) if args.semantic_dir else None
            report_dir = Path(args.report_dir) if args.report_dir else None

            print(f"[2/5] Extracting protocol data from Capture A ({pcap_a.name})...")
            raw_a = extract_all(pcap_a)
            print(f"[3/5] Extracting protocol data from Capture B ({pcap_b.name})...")
            raw_b = extract_all(pcap_b)

            print("[4/5] Building semantic summaries...")
            semantic_a = reduce_to_semantic(raw_a)
            semantic_b = reduce_to_semantic(raw_b)
            json_a = save_semantic_json(semantic_a, pcap_a, semantic_dir)
            json_b = save_semantic_json(semantic_b, pcap_b, semantic_dir)
            print(f"      Saved: {json_a}")
            print(f"      Saved: {json_b}")

            print("[5/5] Generating comparative report via Gemini...")
            prompt = build_compare_prompt(semantic_a, semantic_b)
            report_text = call_gemini(prompt)
            report_path = save_comparison_report(
                report_text, pcap_a, pcap_b, report_dir)
            print(f"      Saved: {report_path}")
            print("\nDone.")
        else:
            # --- Single-capture mode ---
            print("[1/4] Validating input...")
            pcap_path = validate_input(args.pcap)

            semantic_dir = Path(args.semantic_dir) if args.semantic_dir else None
            report_dir = Path(args.report_dir) if args.report_dir else None

            print("[2/4] Extracting protocol data via tshark...")
            raw_data = extract_all(pcap_path)

            print("[3/4] Building semantic summary...")
            semantic = reduce_to_semantic(raw_data)
            json_path = save_semantic_json(semantic, pcap_path, semantic_dir)
            print(f"      Saved: {json_path}")

            print("[4/4] Generating forensic report via Gemini...")
            report_text = generate_report(semantic)
            report_path = save_report(report_text, pcap_path, report_dir)
            print(f"      Saved: {report_path}")

            print("\nDone.")

    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
