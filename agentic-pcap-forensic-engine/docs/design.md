 Design: Agentic PCAP Forensic Engine

> This tool is a single-file CLI with a linear pipeline. A separate high-level and low-level design would be artificial — the code is flat enough that one level of detail covers both the structure and the internals.

---

## Function Map

All functions live in `pcap_forensics.py`. The call graph is strictly top-down — no circular dependencies, no callbacks.

```
main()
 ├── [single-capture mode]
 │    ├── validate_input(args)                     # Stage 1
 │    ├── extract_all(pcap_path)                   # Stage 2
 │    │    ├── extract_capture_summary(pcap_path)
 │    │    ├── extract_arp(pcap_path)
 │    │    ├── extract_icmp(pcap_path)
 │    │    ├── extract_tcp(pcap_path)
 │    │    └── extract_dns(pcap_path)
 │    │         (all extractors call run_tshark)    # shared helper
 │    ├── reduce_to_semantic(raw_data)             # Stage 3
 │    │    ├── reduce_arp(raw)
 │    │    ├── reduce_icmp(raw)
 │    │    ├── reduce_tcp(raw)
 │    │    └── reduce_dns(raw)
 │    │         (all reducers call compute_stats)   # shared helper
 │    ├── save_semantic_json(semantic, pcap_path)
 │    ├── generate_report(semantic)                # Stage 4
 │    │    ├── build_prompt(semantic)
 │    │    └── call_gemini(prompt)
 │    └── save_report(report_text, pcap_path)
 │
 └── [compare mode — --compare flag]
      ├── validate_input(pcap_a)                   # Stage 1 (×2)
      ├── validate_input(pcap_b)
      ├── extract_all(pcap_a)                      # Stage 2 (×2)
      ├── extract_all(pcap_b)
      ├── reduce_to_semantic(raw_a)                # Stage 3 (×2)
      ├── reduce_to_semantic(raw_b)
      ├── save_semantic_json(semantic_a, pcap_a)
      ├── save_semantic_json(semantic_b, pcap_b)
      ├── build_compare_prompt(semantic_a, semantic_b)  # Stage 4 (compare)
      ├── call_gemini(prompt)
      └── save_comparison_report(report_text, pcap_a, pcap_b)
```

---

## Function Signatures and Responsibilities

### Entry Point

```python
def main() -> None
```
- Parses `sys.argv[1]` as the pcap path
- Calls each stage in sequence
- Prints progress to stdout (e.g., `"Extracting ARP data..."`, `"Generating report..."`)
- Wraps everything in a top-level try/except that prints user-friendly messages and exits with code 1 on failure
- No return value; writes two files to disk as side effects (single-capture mode) or three files (compare mode)

### Stage 1 — Validation

```python
def validate_input(args: list[str]) -> Path
```
- **Input:** `sys.argv` (the full argument list)
- **Returns:** validated `Path` to the pcap file
- **Exits with error if:**
  - No argument provided → print usage message
  - File does not exist or is not readable
  - Extension is not `.pcap` or `.pcapng`
  - `tshark` is not found on PATH (`shutil.which("tshark")`)
  - `GEMINI_API_KEY` environment variable is not set

### Stage 2 — Extraction

```python
def run_tshark(pcap_path: Path, fields: list[str], display_filter: str) -> list[list[str]]
```
The shared workhorse. Every protocol extractor calls this.
- **Input:** pcap path, list of tshark field names, display filter string
- **Builds and runs:** `tshark -r <pcap> -Y <filter> -T fields -e <field1> -e <field2> ... -E separator=\t -E header=n`
- **Returns:** list of rows, each row a list of tab-split string values
- **On tshark failure:** raises `RuntimeError` with tshark's stderr

```python
def extract_capture_summary(pcap_path: Path) -> dict
```
- Runs `tshark -r <pcap> -T fields -e frame.number -e frame.time_epoch` with no display filter
- **Streams output line by line** — does NOT load all rows into memory. Tracks only: line count (incremented per row), first timestamp (from first row), and last timestamp (overwritten each row)
- Returns: `{"file": str, "total_packets": int, "duration_seconds": float}`
- Duration is computed as `last_timestamp - first_timestamp`
- Note: this function calls `run_tshark` like the others, but processes the result with a streaming pass rather than storing it

```python
def extract_arp(pcap_path: Path) -> list[dict]
def extract_icmp(pcap_path: Path) -> list[dict]
def extract_tcp(pcap_path: Path) -> list[dict]
def extract_dns(pcap_path: Path) -> list[dict]
```
Each returns a list of per-packet dicts with typed values (ints, floats, strings) parsed from tshark's tab-separated output. See the tshark commands section below for exact fields.

```python
def extract_all(pcap_path: Path) -> dict
```
- Calls each extractor
- Returns: `{"summary": {...}, "arp": [...], "icmp": [...], "tcp": [...], "dns": [...]}`

### Stage 3 — Semantic Reduction

```python
def compute_stats(values: list[float]) -> dict
```
- **Input:** list of numeric values (e.g., RTTs, deltas)
- **Returns:** `{"min": float, "median": float, "p95": float, "max": float}`
- Uses `statistics.median()` for median
- p95 = value at index `int(len(sorted_values) * 0.95)`
- Returns all zeros if input list is empty

```python
def reduce_arp(raw: list[dict]) -> dict
def reduce_icmp(raw: list[dict]) -> dict
def reduce_tcp(raw: list[dict]) -> dict
def reduce_dns(raw: list[dict]) -> dict
```
Each takes the raw per-packet list from Stage 2 and returns the corresponding section of the Semantic JSON (see architecture.md for the schema). Reduction logic is detailed per-protocol below.

```python
def reduce_to_semantic(raw_data: dict) -> dict
```
- Calls each reducer
- Assembles the full Semantic JSON dict with `capture_summary` + all protocol sections
- Derives `protocols_present` from which extractors returned non-empty results (e.g., if `raw_data["arp"]` is empty, "ARP" is excluded from the list)
- Omits protocol sections entirely if there are zero packets for that protocol (keeps JSON compact)
- The `capture_summary.file` field comes from `raw_data["summary"]["file"]` — no need for `pcap_path`

```python
def save_semantic_json(semantic: dict, pcap_path: Path) -> Path
```
- Writes `json.dumps(semantic, indent=2)` to `<pcap_stem>_semantic.json` in the same directory as the input file
- Returns the output path (printed to stdout for user visibility)

### Stage 4 — AI Diagnosis

```python
def generate_report(semantic: dict) -> str
```
- Orchestrator for Stage 4. Calls `build_prompt()` then `call_gemini()`.
- Returns the AI's response text (the Markdown report body)

```python
def build_prompt(semantic: dict) -> str
```
- Constructs the full prompt string. See prompt template section below.

```python
def call_gemini(prompt: str) -> str
```
- Reads `GEMINI_API_KEY` from environment
- Calls `google.genai.Client(api_key=...).models.generate_content(model="gemini-2.0-flash", contents=prompt)`
- Returns `response.text`
- On API error: raises `RuntimeError` with sanitized message (no API key in error text)

```python
def save_report(report_text: str, pcap_path: Path) -> Path
```
- Writes the AI response to `<pcap_stem>_forensic_report.md` in the same directory as the input file
- Returns the output path

### Stage 4 — Comparative Analysis (Compare Mode)

```python
def build_compare_prompt(semantic_a: dict, semantic_b: dict) -> str
```
- Constructs the comparison prompt by formatting `COMPARE_PROMPT_TEMPLATE` with both semantic JSONs
- Returns the full prompt string with both captures embedded

```python
def save_comparison_report(report_text: str, pcap_a: Path, pcap_b: Path,
                           output_dir: Path | None = None) -> Path
```
- Writes the AI comparison response to `<stem_a>_vs_<stem_b>_comparison.md`
- Output directory defaults to the same directory as `pcap_a`, or `output_dir` if provided
- Returns the output path

**`COMPARE_PROMPT_TEMPLATE`** — A separate prompt template (not a modification of `PROMPT_TEMPLATE`) that instructs the AI to perform comparative analysis. Key differences from the single-capture prompt:
- Receives two semantic JSONs labelled "Capture A (baseline)" and "Capture B (current)"
- Comparison framework covers ARP, ICMP, TCP, DNS, and cross-capture correlation
- Output format includes: Executive Summary, Change Summary Table, New Issues, Resolved Issues, Regressions, and Remediation
- Rules emphasize comparing RATES and RATIOS (not raw counts) since captures may differ in duration/volume
- Uses thresholds: <10% change = STABLE, 10-50% = noteworthy, >50% = significant, >200% = critical

### Compare Mode Console Output

```
$ python pcap_forensics.py /path/to/baseline.pcap --compare /path/to/current.pcap

[1/5] Validating inputs...
[2/5] Extracting protocol data from Capture A (baseline.pcap)...
      ARP:  10 packets
      ICMP: 20 packets
      TCP:  150 packets
      DNS:  20 packets
[3/5] Extracting protocol data from Capture B (current.pcap)...
      ARP:  10 packets
      ICMP: 20 packets
      TCP:  180 packets
      DNS:  40 packets
[4/5] Building semantic summaries...
      Saved: /path/to/baseline_semantic.json
      Saved: /path/to/current_semantic.json
[5/5] Generating comparative report via Gemini...
      Saved: /path/to/baseline_vs_current_comparison.md

Done.
```

### Compare Mode Edge Cases

| Scenario | Behavior |
|----------|----------|
| Pcaps with different protocols present | Each pcap's semantic JSON includes only its protocols. The AI handles asymmetry — e.g., DNS in A but not B means DNS was removed/stopped. |
| Very different capture durations | The comparison prompt instructs the AI to normalize by rates (using `avg_packets_per_second` and `duration_seconds`), not raw counts. |
| Same pcap compared with itself | All metrics will be STABLE. Valid but not useful. |
| Comparison report naming | `<stem_a>_vs_<stem_b>_comparison.md` — always uses pcap_a's directory unless `--report-dir` overrides. |

---

## tshark Commands

Each command extracts **metadata only** — no payload fields are ever requested.

### Capture Summary

```bash
tshark -r <pcap> -T fields -e frame.number -e frame.time_epoch \
  -E separator=$'\t' -E header=n
```

This runs without a display filter (reads every packet). To avoid holding all rows in memory, `extract_capture_summary` reads tshark's stdout **line by line**: it stores the timestamp from the first line, overwrites a `last_timestamp` variable on each subsequent line, and increments a counter. Only three values are kept in memory regardless of pcap size.

### ARP (Layer 2)

```bash
tshark -r <pcap> -Y "arp" -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e arp.opcode \
  -e arp.src.hw_mac \
  -e arp.src.proto_ipv4 \
  -e arp.dst.proto_ipv4 \
  -E separator=$'\t' -E header=n
```

**Parsed fields:**
| Field | Type | Notes |
|-------|------|-------|
| `frame.number` | int | Packet number for anomaly references |
| `frame.time_epoch` | float | Epoch timestamp |
| `arp.opcode` | int | 1 = Request, 2 = Reply |
| `arp.src.hw_mac` | str | Source MAC |
| `arp.src.proto_ipv4` | str | Source IP |
| `arp.dst.proto_ipv4` | str | Target IP (who is being asked about) |

### ICMP (Layer 3)

```bash
tshark -r <pcap> -Y "icmp" -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e icmp.type \
  -e icmp.code \
  -e icmp.seq \
  -e icmp.resp_in \
  -e frame.time_delta \
  -e ip.src \
  -e ip.dst \
  -E separator=$'\t' -E header=n
```

**Parsed fields:**
| Field | Type | Notes |
|-------|------|-------|
| `icmp.type` | int | 0 = Echo Reply, 3 = Dest Unreachable, 5 = Redirect, 8 = Echo Request, 11 = Time Exceeded |
| `icmp.code` | int | Subtype — critical for Type 3: 0=Net, 1=Host, 3=Port, 4=Frag Needed (PMTUD), 9/10/13=Admin Prohibited |
| `icmp.seq` | int | Sequence number for matching req/reply |
| `icmp.resp_in` | int or empty | Frame number of the matching reply (empty if unanswered) |
| `frame.time_delta` | float | Time since previous displayed packet |
| `ip.src` | str | Source IP — identifies which host generated the ICMP message (critical for Type 3/5/11) |
| `ip.dst` | str | Destination IP — identifies the intended target |

### TCP (Layer 4)

```bash
tshark -r <pcap> -Y "tcp" -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e tcp.stream \
  -e ip.src \
  -e tcp.srcport \
  -e ip.dst \
  -e tcp.dstport \
  -e tcp.flags \
  -e tcp.analysis.retransmission \
  -e tcp.analysis.duplicate_ack \
  -e tcp.analysis.out_of_order \
  -e tcp.analysis.zero_window \
  -e tcp.analysis.ack_rtt \
  -e tcp.len \
  -e tcp.window_size_value \
  -e tcp.time_delta \
  -E separator=$'\t' -E header=n
```

**Parsed fields:**
| Field | Type | Notes |
|-------|------|-------|
| `tcp.stream` | int | Stream index (groups related packets) |
| `ip.src`, `tcp.srcport` | str, int | Source endpoint |
| `ip.dst`, `tcp.dstport` | str, int | Destination endpoint |
| `tcp.flags` | hex str | e.g., `0x0002` (SYN), `0x0012` (SYN-ACK), `0x0004` (RST) |
| `tcp.analysis.retransmission` | str | Present (non-empty) if this is a retransmission |
| `tcp.analysis.duplicate_ack` | str | Present if this is a duplicate ACK (indicator of packet loss; 3+ dup ACKs trigger Fast Retransmit per RFC 5681) |
| `tcp.analysis.out_of_order` | str | Present if packet arrived out of sequence (path reordering, ECMP/LAG issue) |
| `tcp.analysis.zero_window` | str | Present if receiver advertised zero window (application not reading fast enough — app-layer bottleneck) |
| `tcp.analysis.ack_rtt` | float | Round-trip time measured from data segment to its ACK (more accurate than `tcp.time_delta` for RTT) |
| `tcp.len` | int | TCP payload length in bytes |
| `tcp.window_size_value` | int | Receive window size advertised by this packet's sender |
| `tcp.time_delta` | float | Time since previous packet in this TCP stream |

**Flag parsing:** The hex flags value is decoded using bitmask constants:
```python
SYN = 0x0002
ACK = 0x0010
RST = 0x0004
FIN = 0x0001
```

### DNS (Layer 7)

```bash
tshark -r <pcap> -Y "dns" -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e dns.id \
  -e dns.flags.response \
  -e dns.qry.name \
  -e dns.qry.type \
  -e dns.flags.rcode \
  -e dns.time \
  -e dns.count.answers \
  -e dns.flags.truncated \
  -e ip.dst \
  -E separator=$'\t' -E header=n
```

**Parsed fields:**
| Field | Type | Notes |
|-------|------|-------|
| `dns.id` | int (hex) | Transaction ID for matching query to response |
| `dns.flags.response` | bool str | "True"/"False" or "1"/"0" — indicates query vs response |
| `dns.qry.name` | str | Domain name queried |
| `dns.qry.type` | int | Query type: 1=A, 2=NS, 5=CNAME, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV, 255=ANY |
| `dns.flags.rcode` | int | 0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED |
| `dns.time` | float or empty | Response time in seconds (only present on responses) |
| `dns.count.answers` | int | Number of answer records — 0 answers with NOERROR = empty response (upstream misconfiguration) |
| `dns.flags.truncated` | bool str | "True" if response was truncated (too large for UDP, should trigger TCP fallback) |
| `ip.dst` | str | On queries: identifies which DNS server was queried |

### Parsing Notes (apply to all extractors)

**Empty fields:** tshark outputs an empty string when a field is not present on a packet (e.g., `tcp.analysis.retransmission` on a normal packet, `icmp.resp_in` on an unanswered request, `dns.time` on a query). During parsing, empty strings are converted to `None`. Downstream code checks for `None` before using these values.

**Boolean fields:** Some tshark fields return `"True"`/`"False"` instead of `1`/`0` (e.g., `dns.flags.response`, `dns.flags.truncated`). These are normalized to int 1/0 during extraction.

**Hex integer fields:** Some fields return hex strings (e.g., `dns.id` as `"0x0100"`, `tcp.flags` as `"0x0012"`). Parsed via `int(value, 0)` (auto-detects base) for general hex ints, or `int(value, 16)` for fields that are always hex (tcp.flags).

**Boolean-present fields:** Analysis fields like `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack`, `tcp.analysis.out_of_order`, and `tcp.analysis.zero_window` are "present when true" — tshark outputs a non-empty value when the condition is detected, and an empty string otherwise. Parsed to Python `bool` via `bool(value.strip())`.

**Unit conversions:** tshark outputs all time values in **seconds** (`frame.time_delta`, `tcp.time_delta`, `tcp.analysis.ack_rtt`, `dns.time`). The Semantic JSON reports timing in **milliseconds** for readability by network engineers. Conversion (`value * 1000`) happens in the reduction stage, not during extraction — extractors store raw seconds.

**Hex flag parsing:** `tcp.flags` is output as a hex string (e.g., `"0x0002"`, `"0x0012"`). Parsed to `int` via `int(value, 16)` in the extractor, then tested with bitmask constants in the reducer.

---

## Semantic Reduction Logic

### ARP Reduction

1. Count packets where `opcode == 1` → `total_requests`
2. Count packets where `opcode == 2` → `total_replies`
3. Detect gratuitous ARP: `src_ip == dst_ip` → `gratuitous_arp_count`. These are excluded from the unanswered check (gratuitous ARPs are announcements, not queries — they don't expect a reply).
4. For each non-gratuitous request, check if a matching reply exists (same target IP has a reply from that IP). Collect unmatched requests, grouped by target IP → `unanswered_requests`

**IP-MAC conflict detection (new):**
5. Build an `ip → set(mac)` mapping from all ARP packets (both requests and replies — use `src_ip → src_mac`). When a single IP maps to more than one MAC address, this is a `duplicate_ip_alert` — a critical finding that indicates either ARP spoofing/cache poisoning, VRRP/HSRP failover, NIC teaming, or a genuine IP conflict. Include the IP, all observed MACs, and sample frame numbers for the first packet from each MAC → `duplicate_ip_alerts`. This list is only populated when conflicts exist (keeps JSON compact for clean captures).

### ICMP Reduction

**Echo Request/Reply analysis (unchanged):**
1. Build a lookup map: `frame_number → timestamp` from all ICMP packets
2. Separate Echo Requests (`type == 8`) and Echo Replies (`type == 0`)
3. For each request with a non-`None` `resp_in` (or matching reply by seq as fallback), look up the reply's timestamp from the map. RTT = `reply_timestamp - request_timestamp` (converted to milliseconds). Count these → `echo_pairs_matched`
4. Requests with no matching reply → `echo_unmatched`
5. Collect all RTT values → `rtt_ms` stats via `compute_stats()`
6. **Anomaly detection:** any RTT > 2x median → add to `anomalies` list with seq, rtt_ms, and frame number of the request

**Type distribution (new):**
7. Count all ICMP packets by type → `type_distribution` dict. Map type codes to human-readable names: 0→echo_reply, 3→dest_unreachable, 5→redirect, 8→echo_request, 11→time_exceeded. Unknown types use `type_N`.

**Destination Unreachable analysis (new — Type 3):**
8. Group Type 3 packets by (src, dst, code). For each group, include count, code meaning (map: 0=Network Unreachable, 1=Host Unreachable, 3=Port Unreachable, 4=Fragmentation Needed/DF Set, 9=Net Admin Prohibited, 10=Host Admin Prohibited, 13=Communication Admin Prohibited), and a sample frame → `unreachable_details`

**Redirect analysis (new — Type 5):**
9. Group Type 5 packets by source. Include the gateway IP from `ip.dst` (the redirect target), count, and sample frame → `redirect_details`

**TTL Exceeded analysis (new — Type 11):**
10. Group Type 11 packets by source IP → `ttl_exceeded_sources` with count and sample frame. Multiple TTL exceeded from the same source = routing loop indicator.

### TCP Reduction

**Per-stream analysis:**
1. Group all packets by `tcp.stream`
2. Per stream, compute:
   - SYN, ACK, RST, FIN counts (from flag bitmasks)
   - Retransmission count (non-empty `tcp.analysis.retransmission` field)
   - Duplicate ACK count (non-empty `tcp.analysis.duplicate_ack` field)
   - Out-of-order count (non-empty `tcp.analysis.out_of_order` field)
   - Zero-window event count (non-empty `tcp.analysis.zero_window` field)
   - Collect frame numbers of retransmission, dup-ack, out-of-order, zero-window, and RST packets → `notable_frames_set` (for anomaly citing)
   - Inter-packet delta stats via `compute_stats()` (converted to milliseconds)
   - ACK RTT stats from `tcp.analysis.ack_rtt` values via `compute_stats()` → `ack_rtt_ms` (more accurate than delta for measuring actual round-trip time)
   - Endpoint pair: `src_ip:src_port` → `dst_ip:dst_port` (from first packet in stream)
3. Aggregate across all streams: `streams_total`, `retransmissions_total`, `rst_count`, `duplicate_ack_total`, `out_of_order_total`, `zero_window_total`

**Connection lifecycle analysis (new):**
4. Compute `connection_stats` across all streams:
   - `syn_sent`: count of packets with SYN flag set (no ACK) — connection initiation attempts
   - `syn_ack_received`: count of packets with SYN+ACK — server accepted connection
   - `handshakes_completed`: count of streams that have at least one SYN, one SYN-ACK, and one subsequent ACK — fully established connections
   - `handshake_success_rate_pct`: `handshakes_completed / syn_sent * 100` (0.0 if no SYNs)
   - `rst_teardowns`: count of streams containing RST — abnormal termination
   - `fin_teardowns`: count of streams containing FIN — graceful termination

**Anomaly filter for `streams_with_issues`:**
5. Include a stream if **any** of:
   - retransmissions > 0
   - duplicate ACKs > 0
   - out-of-order packets > 0
   - zero-window events > 0
   - RST flag present
   - p95 delta > 2x overall median delta
6. Each entry in `streams_with_issues` includes per-stream counts for retransmissions, duplicate_acks, out_of_order, zero_window_events, plus `ack_rtt_ms` stats, `delta_ms` stats, and `sample_frames` (up to 5 frame numbers of the most notable packets). Capped at 5 to keep the JSON compact.

### DNS Reduction

**Core matching (unchanged):**
1. Separate queries (`flags.response == 0`) and responses (`flags.response == 1`)
2. Count each → `queries_total`, `responses_total`
3. Unmatched queries (query `dns.id` with no corresponding response `dns.id`) → `unanswered_queries`
4. Group response rcodes → `rcode_distribution` dict (map rcode int to name: 0→NOERROR, 2→SERVFAIL, 3→NXDOMAIN, etc.)
5. Collect `dns.time` values from responses → `latency_ms` stats via `compute_stats()`
6. **Anomaly filter for `slow_queries`:** responses where `dns.time` > 2x median → include with query name, latency, and frame number

**Query type distribution (new):**
7. Count queries by `dns.qry.type` → `query_type_distribution` dict. Map type codes to names: 1→A, 2→NS, 5→CNAME, 12→PTR, 15→MX, 16→TXT, 28→AAAA, 33→SRV, 255→ANY. Unknown types use `TYPE_N`. High TXT ratio (>20% of queries) is a DNS tunneling indicator. ANY queries suggest amplification attack preparation.

**NXDOMAIN domain names (new):**
8. Collect domain names from responses with rcode=3 (NXDOMAIN), grouped by name → `nxdomain_domains` list with name, count, and sample frame. Capped at top 10 by count. Random-looking names may indicate DGA malware. Misspelled legitimate names indicate misconfiguration.

**SERVFAIL domain names (new):**
9. Collect domain names from responses with rcode=2 (SERVFAIL), grouped by name → `servfail_domains` list with name, count, and sample frame. These identify specific zones or authoritative servers that are broken.

**Top queried domains (new):**
10. Count queries by domain name → `top_queried_domains` list, sorted by count descending, capped at top 10. High volume for a single domain may indicate polling misconfiguration or targeted scanning.

**DNS server distribution (new):**
11. Collect unique `ip.dst` values from query packets → `dns_servers_queried` list. Identifies all DNS servers in use — unexpected servers may indicate DNS hijacking or misconfigured resolv.conf.

**Truncated responses (new):**
12. Count responses with `dns.flags.truncated` set → `truncated_responses`. Indicates responses too large for UDP — client should retry over TCP. High count suggests EDNS0 issues or large zone responses.

---

## AI Prompt Template

The prompt is divided into three parts: (1) the analyst persona and analysis framework with protocol-specific diagnostic patterns, (2) the output format specification, and (3) the semantic JSON data. This structure ensures the AI performs root-cause analysis at an expert level rather than surface-level summarization.

```
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
    200ms→400ms→800ms) = RTO-based retransmission, meaning even Fast
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
--- END SEMANTIC JSON ---
```

The `{semantic_json}` placeholder is replaced with `json.dumps(semantic, indent=2)`.

### Comparison Prompt Template

The `COMPARE_PROMPT_TEMPLATE` is a separate constant (not a modification of `PROMPT_TEMPLATE`). It contains `{semantic_json_a}` and `{semantic_json_b}` placeholders, replaced by `build_compare_prompt()` with `json.dumps(semantic_a, indent=2)` and `json.dumps(semantic_b, indent=2)` respectively.

The comparison prompt differs from the single-capture prompt in these ways:
- **Input structure**: Two semantic JSONs delimited by `--- BEGIN CAPTURE A (BASELINE) ---` / `--- END CAPTURE A ---` and `--- BEGIN CAPTURE B (CURRENT) ---` / `--- END CAPTURE B ---`
- **Comparison framework**: Protocol-specific comparison dimensions (ARP conflict changes, ICMP RTT regression, TCP retransmission rate changes, DNS NXDOMAIN deltas, cross-capture correlation)
- **Output sections**: Executive Summary, Change Summary Table (with Assessment: REGRESSION/IMPROVEMENT/STABLE/NEW ISSUE/RESOLVED), New Issues, Resolved Issues, Regressions, Remediation
- **Normalization rules**: Compare rates and ratios, not raw counts. Thresholds: <10% STABLE, 10-50% noteworthy, >50% significant, >200% critical

The full template text is in `pcap_forensics.py` as `COMPARE_PROMPT_TEMPLATE`.

---

## Output File Naming

Both output files are placed in the **same directory** as the input pcap file (or in `--semantic-dir` / `--report-dir` if specified).

| Mode | Input | Semantic JSON Output | Report Output |
|------|-------|---------------------|---------------|
| Single | `/path/to/capture.pcap` | `/path/to/capture_semantic.json` | `/path/to/capture_forensic_report.md` |
| Single | `/data/test.pcapng` | `/data/test_semantic.json` | `/data/test_forensic_report.md` |
| Compare | `baseline.pcap --compare current.pcap` | `baseline_semantic.json` + `current_semantic.json` | `baseline_vs_current_comparison.md` |

Naming uses `Path.stem` (filename without extension) + the fixed suffix.

---

## Console Output

The tool prints progress to stdout so the user knows what's happening. No spinners or progress bars — just plain text lines.

```
$ python pcap_forensics.py /path/to/capture.pcap

[1/4] Validating input...
[2/4] Extracting protocol data via tshark...
      ARP:  15 packets
      ICMP: 205 packets
      TCP:  11,842 packets
      DNS:  395 packets
[3/4] Building semantic summary...
      Saved: /path/to/capture_semantic.json
[4/4] Generating forensic report via Gemini...
      Saved: /path/to/capture_forensic_report.md

Done.
```

---

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| pcap has no ARP/ICMP/TCP/DNS traffic | Semantic JSON omits empty protocol sections. AI prompt still sent — AI reports "no anomalies." |
| pcap has only one protocol | Only that protocol section appears in the Semantic JSON. |
| tshark returns empty output for a protocol | Extractor returns an empty list. Reducer produces nothing. Section omitted from Semantic JSON. |
| Very large pcap (>100MB) | tshark may be slow but will still work. `extract_capture_summary` streams line by line (does not hold all rows in memory). Protocol extractors do hold their rows in memory, but protocol-filtered subsets are much smaller than the full capture. |
| Duplicate/overlapping TCP streams | Handled naturally by grouping on `tcp.stream` index (tshark assigns unique IDs). |
| DNS query with multiple answers | `dns.id` matching handles this — one query ID maps to one response. Multiple answer records in a single response are not extracted (only rcode and latency matter). |
| DNS transaction ID reuse | `dns.id` is a 16-bit field and can be reused across the capture. Matching is done by pairing the closest query and response with the same ID. In practice, tshark's `dns.time` field already handles this correctly. |
| Output files already exist | Overwritten silently. Each run produces a fresh analysis — there is no append or versioning. |
| tshark field returns multiple values | Some fields (e.g., `dns.qry.name`) can have multiple comma-separated values in a single row. The extractor takes the first value only. |
| No ICMP Destination Unreachable packets | `unreachable_details` is an empty list. `type_distribution` still computed from whatever types are present. |
| ARP with only one MAC per IP | `duplicate_ip_alerts` is an empty list (no conflicts). Only populated when conflicts exist. |
| TCP stream with only SYN (no SYN-ACK) | Stream is counted in `syn_sent` but not in `syn_ack_received`. Reduces `handshake_success_rate_pct`. |
| DNS with all NOERROR | `nxdomain_domains` and `servfail_domains` are empty lists. `rcode_distribution` shows only `{"NOERROR": N}`. |
| `tcp.analysis.ack_rtt` absent on all packets | `ack_rtt_ms` stats default to all zeros. Delta-based timing still available as fallback. |
| Top queried domains / NXDOMAIN lists | Capped at top 10 by count to keep the Semantic JSON within the <5,000 token budget even for captures with thousands of unique domains. |
