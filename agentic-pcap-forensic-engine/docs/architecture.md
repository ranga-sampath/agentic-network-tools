# Architecture: Agentic PCAP Forensic Engine

## Design Decisions

| Decision | Choice | Rationale (per sw-principles) |
|----------|--------|-------------------------------|
| Language | Python 3.10+ | Single-language stack; familiar; rich ecosystem for subprocess/JSON handling |
| Architecture | Monolithic CLI | Simplicity over sophistication; no need for services or a web UI |
| Packet Parsing | `tshark` via subprocess | Leverage existing battle-tested tool; avoid reinventing pcap parsing |
| AI Provider | Gemini API (Google GenAI SDK) | Direct SDK call; pay-per-use with no fixed infrastructure cost; user already has access. Provider is swappable (see AI Provider Portability section below) |
| Config/Secrets | Environment variables | `GEMINI_API_KEY` from env; no secrets in code |
| Output | Semantic JSON + Markdown report to disk | Two artifacts: the structured data (reusable) and the AI-generated report (human-readable) |

---

## High-Level Pipeline

The tool is a **linear four-stage pipeline** executed as a single CLI invocation.

```
┌──────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│   Stage 1    │     │     Stage 2      │     │     Stage 3       │     │     Stage 4      │
│   Validate   │────>│  Extract (tshark)│────>│ Semantic Reduction│────>│  AI Diagnosis +  │
│   Input      │     │  per-protocol    │     │  (compact JSON)   │     │  Report Output   │
└──────────────┘     └──────────────────┘     └────────┬──────────┘     └────────┬─────────┘
     .pcap               raw JSON                      │                         │
                                                       ▼                         ▼
                                                 *_semantic.json          *_forensic_report.md
                                                 (saved to disk)          (saved to disk)
```

---

## Stage Details

### Stage 1 — Input Validation

- Verify file exists and is readable
- Verify extension is `.pcap` or `.pcapng`
- Verify `tshark` is installed and available on PATH
- Verify `GEMINI_API_KEY` is set
- Fail fast with user-friendly error messages (no raw tracebacks)

### Stage 2 — Protocol Extraction (tshark)

Run targeted `tshark` commands to extract **metadata only** (no payloads — privacy requirement).

| Protocol | tshark Filter / Key Fields | Diagnostic Signals |
|----------|---------------------------|-------------------|
| **ARP** (L2) | `arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.proto_ipv4` | Request/reply matching, unanswered requests, gratuitous ARPs, **IP-MAC conflict detection** (ARP spoofing) |
| **ICMP** (L3) | `icmp.type`, `icmp.code`, `icmp.seq`, `icmp.resp_in`, `ip.src`, `ip.dst` | Echo RTT analysis, **Destination Unreachable by code** (host down, port closed, PMTUD black hole, firewall reject), **TTL Exceeded** (routing loops), **Redirect** (MITM/routing issues) |
| **TCP** (L4) | `tcp.flags`, `tcp.stream`, `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack`, `tcp.analysis.out_of_order`, `tcp.analysis.zero_window`, `tcp.analysis.ack_rtt`, `tcp.len`, `tcp.window_size_value` | Connection success rate, retransmission patterns, **zero-window stalls** (app bottleneck), **duplicate ACK / fast retransmit**, **out-of-order** (ECMP/LAG reordering), **ACK RTT distribution** (bufferbloat) |
| **DNS** (L7) | `dns.qry.name`, `dns.qry.type`, `dns.flags.rcode`, `dns.flags.response`, `dns.flags.truncated`, `dns.time`, `dns.count.answers`, `ip.dst` | Query type distribution, **NXDOMAIN domain names** (DGA malware, misconfiguration), **SERVFAIL domains** (zone failures), **truncated responses** (EDNS0 issues), **DNS server distribution**, **top queried domains** |

Each extraction is a separate `tshark` invocation with `-T fields` output, parsed into Python dicts.

### Stage 3 — Semantic Reduction

Convert raw per-packet data into a compact **Semantic JSON** structure.

**Why Semantic JSON?** A raw 10MB pcap can contain hundreds of thousands of packets. Sending that volume of data directly to an AI would be prohibitively expensive (millions of tokens) and would overwhelm the model's context window. The Semantic JSON is the critical bridge — it structures and compresses the data through aggregation, statistical summaries, and anomaly filtering so that the AI receives everything it needs for an accurate diagnosis in under 5,000 tokens, without any loss of forensically relevant information. The reduction is in volume, not in accuracy.

**Saved to disk:** The Semantic JSON is written to disk as `<capture_name>_semantic.json` alongside the input file. This gives network engineers a structured, machine-readable artifact they can feed into their own scripts, dashboards, monitoring tools, or diff across captures — independent of the AI report.

**Reduction strategies:**
- **Count, don't list** — e.g., "TCP retransmissions: 47" instead of listing all 47 packets
- **Group by conversation** — aggregate per TCP stream, per DNS query name, per ICMP sequence
- **Surface anomalies only** — include individual packet details only for statistical outliers (e.g., RTT > 2x median)
- **Timing summaries** — min/median/max/p95 instead of raw delta arrays

**Semantic JSON skeleton:**
```json
{
  "capture_summary": {
    "file": "example.pcap",
    "total_packets": 12340,
    "duration_seconds": 45.2,
    "protocols_present": ["ARP", "ICMP", "TCP", "DNS"],
    "avg_packets_per_second": 273.0
  },
  "arp": {
    "total_requests": 15,
    "total_replies": 12,
    "unanswered_requests": [ {"ip": "10.0.0.5", "count": 3} ],
    "gratuitous_arp_count": 0,
    "duplicate_ip_alerts": [
      {"ip": "10.0.0.5", "macs": ["aa:bb:cc:dd:ee:05", "ff:ee:dd:cc:bb:aa"],
       "sample_frames": [12, 47]}
    ]
  },
  "icmp": {
    "echo_pairs_matched": 100,
    "echo_unmatched": 5,
    "rtt_ms": {"min": 1.2, "median": 4.5, "p95": 22.0, "max": 310.0},
    "anomalies": [ {"seq": 42, "rtt_ms": 310.0, "frame": 1023} ],
    "type_distribution": {
      "echo_request": 105, "echo_reply": 100,
      "dest_unreachable": 12, "time_exceeded": 3, "redirect": 1
    },
    "unreachable_details": [
      {"src": "10.0.0.1", "dst": "192.168.1.50", "code": 1,
       "code_meaning": "Host Unreachable", "count": 5, "sample_frame": 234}
    ],
    "redirect_details": [
      {"src": "10.0.0.1", "gateway": "10.0.0.254",
       "count": 1, "sample_frame": 301}
    ],
    "ttl_exceeded_sources": [
      {"src": "172.16.0.1", "count": 3, "sample_frame": 789}
    ]
  },
  "tcp": {
    "streams_total": 18,
    "retransmissions_total": 47,
    "rst_count": 3,
    "duplicate_ack_total": 23,
    "out_of_order_total": 5,
    "zero_window_total": 2,
    "connection_stats": {
      "syn_sent": 20,
      "syn_ack_received": 18,
      "handshakes_completed": 17,
      "handshake_success_rate_pct": 85.0,
      "rst_teardowns": 3,
      "fin_teardowns": 14
    },
    "streams_with_issues": [
      {
        "stream_id": 4,
        "src": "10.0.0.1:443",
        "dst": "10.0.0.2:52341",
        "retransmissions": 12,
        "duplicate_acks": 8,
        "out_of_order": 2,
        "zero_window_events": 1,
        "rst": true,
        "ack_rtt_ms": {"min": 0.5, "median": 2.1, "p95": 45.0, "max": 120.0},
        "delta_ms": {"median": 0.5, "p95": 120.0, "max": 850.0},
        "sample_frames": [1042, 1055, 1071, 1089, 1102]
      }
    ]
  },
  "dns": {
    "queries_total": 200,
    "responses_total": 195,
    "unanswered_queries": 5,
    "query_type_distribution": {"A": 150, "AAAA": 30, "PTR": 10, "TXT": 5, "MX": 5},
    "rcode_distribution": {"NOERROR": 190, "NXDOMAIN": 4, "SERVFAIL": 1},
    "latency_ms": {"min": 2.0, "median": 15.0, "p95": 80.0, "max": 500.0},
    "slow_queries": [ {"name": "api.example.com", "latency_ms": 500.0, "frame": 4401} ],
    "nxdomain_domains": [
      {"name": "typo.exmple.com", "count": 3, "sample_frame": 123}
    ],
    "servfail_domains": [
      {"name": "broken-zone.internal", "count": 1, "sample_frame": 456}
    ],
    "top_queried_domains": [
      {"name": "api.example.com", "count": 45},
      {"name": "cdn.example.com", "count": 38}
    ],
    "dns_servers_queried": ["10.0.0.53", "8.8.8.8"],
    "truncated_responses": 0
  }
}
```

### Stage 4 — AI Diagnosis + Report Generation

- Build a **deeply technical prompt** containing the Semantic JSON plus a comprehensive protocol analysis framework. The prompt is not a generic "summarize this data" instruction — it embeds expert-level diagnostic patterns for each protocol so the AI can perform root cause analysis at the level of a senior network engineer:
  - **ARP**: IP-MAC conflict interpretation, spoofing vs. VRRP/HSRP failover distinction
  - **ICMP**: Destination Unreachable code-by-code analysis (host down, port closed, PMTUD black hole, firewall reject), TTL exceeded routing loop detection, redirect attack patterns
  - **TCP**: Connection success rate analysis, retransmission pattern classification (network-wide vs endpoint-specific), zero-window stall root cause (application bottleneck, not network), duplicate ACK / fast retransmit correlation, RST origin analysis (server vs inline device)
  - **DNS**: DGA malware detection from NXDOMAIN patterns, DNS tunneling indicators from query type ratios, zone failure diagnosis from SERVFAIL domains
  - **Cross-protocol correlation**: e.g., ARP unanswered + ICMP Host Unreachable = host down; ICMP Fragmentation Needed + TCP retransmissions on port 443 = PMTUD black hole for HTTPS
- The report includes **severity-classified findings** (CRITICAL/HIGH/MEDIUM/LOW/INFO), a **root cause analysis** section, and **specific CLI commands** for remediation (not generic suggestions)
- Call the Gemini API via the Google GenAI Python SDK (`google.genai`)
- Write Gemini's response directly to a `.md` file on disk

**Privacy safeguard:** The prompt is constructed entirely from the Semantic JSON (Stage 3 output), which contains only metadata and statistics — never packet payloads.

---

## Project Structure

```
nw-forensics/
├── requirements.md
├── sw-principles.md
├── architecture.md
├── requirements.txt          # google-genai SDK, no other heavy deps
├── pcap_forensics.py         # single-file CLI entry point
└── sample/                   # sample pcap files for manual testing
```

**Single file by design.** The entire tool lives in `pcap_forensics.py`. There is no framework, no package structure, no `src/` directory. This keeps the tool simple, portable, and easy to read top-to-bottom. If the file grows beyond ~500 lines, it can be split later — but not preemptively.

---

## CLI Interface

```bash
# Basic usage
python pcap_forensics.py /path/to/capture.pcap

# Two outputs written to same directory as input:
#   /path/to/capture_semantic.json          (structured data)
#   /path/to/capture_forensic_report.md     (AI-generated report)
```

No flags, no config files, no modes. One input, two outputs.

---

## External Dependencies

| Dependency | Type | Purpose |
|------------|------|---------|
| `tshark` | System binary (pre-installed by user) | Packet extraction |
| `google-genai` | Python package | Gemini API calls |

No other dependencies. Standard library (`subprocess`, `json`, `statistics`, `pathlib`, `sys`) handles everything else.

---

## Error Handling Strategy

| Error | Behavior |
|-------|----------|
| File not found / unreadable | Print clear message, exit 1 |
| tshark not installed | Print install instructions for the user's OS, exit 1 |
| tshark fails on pcap | Print tshark stderr (useful for corrupt files), exit 1 |
| API key missing | Print "Set GEMINI_API_KEY environment variable", exit 1 |
| API call fails | Print error message (sanitized — no key leakage), exit 1 |
| Empty pcap / no relevant protocols | Generate report noting "no anomalies detected" instead of failing |

---

## AI Provider Portability

The current implementation uses the **Gemini API** as the AI provider. However, the AI integration is deliberately isolated to a single stage (Stage 4) and consists of just two concerns:

1. **Constructing a prompt** from the Semantic JSON (provider-agnostic — it's just a string)
2. **Making an API call** and reading back the response text

This means the AI provider can be swapped to any other LLM (Claude, OpenAI, a local model, etc.) by changing only the API call function and the corresponding environment variable for the API key. The rest of the pipeline — validation, tshark extraction, semantic reduction, and report file writing — is completely independent of the AI provider.

---

## Future Enhancements

The following are natural extensions that could add value without requiring an architectural rewrite. None of these are planned for the initial version — they are documented here to show the tool's extensibility.

| Enhancement | Description |
|-------------|-------------|
| **Additional protocols** | Add extractors for HTTP (status codes, latency), TLS (handshake failures, cert issues), DHCP (lease problems), or any protocol tshark can decode. Each is an additive change — a new tshark command and a new key in the Semantic JSON. |
| **Comparative analysis** | Accept two pcap files and produce a diff report — useful for "it worked yesterday, it's broken today" scenarios. |
| **Batch mode** | Process a directory of pcap files and produce a summary report across all captures (e.g., recurring DNS failures across multiple time windows). |
| **Interactive mode** | After generating the report, allow the user to ask follow-up questions about the capture by chatting with the AI, with the Semantic JSON as persistent context. |
| **HTML report output** | Offer an HTML report option with collapsible sections and styled anomaly tables, generated from the same Markdown via a lightweight converter. |
| **Threshold configuration** | Allow the user to supply a config file defining what counts as an "anomaly" (e.g., RTT > 100ms instead of the default 2x median), to tailor the report for different network environments. |
| **Offline / local LLM mode** | Support a local model (e.g., Ollama) for air-gapped environments where no data can leave the machine. The prompt and Semantic JSON are already provider-agnostic, so this is a Stage 4 change only. |

---

## What This Architecture Intentionally Omits

| Omitted | Why |
|---------|-----|
| Web UI | CLI is simpler; no auth, no hosting, no frontend framework |
| Database | No persistent state needed; each run is independent |
| Async / concurrency | Pipeline is sequential; tshark calls are fast enough serially |
| Plugin system | One tool, four protocols; extend by editing the file |
| Docker / containerization | User already has tshark; adding Docker adds complexity without benefit |
| Automated tests | Per sw-principles: manual testing for MVPs; tests come after design stabilizes |
