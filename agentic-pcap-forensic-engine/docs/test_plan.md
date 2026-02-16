# Test Plan: PCAP Forensic Engine

## Test Approach

All tests use **synthetic pcap files** generated with Python's `scapy` library. Each pcap is crafted with known packet counts, timings, and anomalies so that expected outputs can be precisely defined. This eliminates reliance on real-world captures where ground truth is unknown.

A test harness script (`generate_test_pcaps.py`) creates all required pcap files into a `test_pcaps/` directory. Each test references a specific pcap by name.

### Test Execution

Tests are run manually against the built tool. For each test:

1. Run `python pcap_forensics.py test_pcaps/<test_file>.pcap`
2. Inspect the generated `_semantic.json` against the expected values listed
3. Inspect the generated `_forensic_report.md` for structural compliance
4. Check console output and exit code where applicable

### Verification Shorthand

- **JSON check** — open the `_semantic.json` and verify specific fields/values
- **Report check** — open the `_forensic_report.md` and verify section presence and content
- **Console check** — observe stdout output
- **Exit check** — verify exit code (0 for success, 1 for failure)

---

## Test Category 1: Input Validation (Stage 1)

These tests verify that the tool rejects bad input early with clear messages.

| ID | Scenario | Input | Expected | Verify |
|----|----------|-------|----------|--------|
| V-01 | No arguments | `python pcap_forensics.py` (no args) | Prints usage message, exits 1 | Exit check, console check |
| V-02 | File does not exist | `python pcap_forensics.py /tmp/nonexistent.pcap` | Prints "File not found: /tmp/nonexistent.pcap", exits 1 | Exit check, console check |
| V-03 | Wrong extension | Create an empty `test.txt` file | Prints error about unsupported file extension, exits 1 | Exit check, console check |
| V-04 | `.pcap` extension accepted | Valid `.pcap` file | Passes validation, proceeds to Stage 2 | Console check (shows "[1/4]" then "[2/4]") |
| V-05 | `.pcapng` extension accepted | Valid `.pcapng` file | Passes validation, proceeds to Stage 2 | Console check |
| V-06 | tshark not on PATH | Temporarily rename/hide tshark binary, run tool | Prints message about tshark not found with install guidance, exits 1 | Exit check, console check |
| V-07 | API key not set | Unset `GEMINI_API_KEY`, run tool | Prints "Set GEMINI_API_KEY environment variable", exits 1 | Exit check, console check |
| V-08 | Unreadable file | Create a `.pcap` file with `chmod 000` | Prints message about file not readable, exits 1 | Exit check, console check |
| V-09 | Successful run exits 0 | Valid pcap with valid API key | Tool completes, exits 0 | Exit check (`echo $?` returns 0) |
| V-10 | Path with spaces | Place valid pcap at `/tmp/test dir/my capture.pcap` | Tool processes it correctly, outputs to same directory | Exit check, output files exist at `/tmp/test dir/` |
| V-11 | Console output format | Valid pcap | Output matches design spec: `[1/4] Validating input...`, `[2/4] Extracting protocol data via tshark...` (with per-protocol counts), `[3/4] Building semantic summary...`, `[4/4] Generating forensic report via Gemini...`, `Done.` | Console check |

---

## Test Category 2: Extraction Correctness (Stage 2)

Each test uses a synthetic pcap with a known, small number of packets to verify that extractors parse fields correctly.

### T-EXT-01: ARP Extraction

**Pcap:** `test_arp_basic.pcap` — 4 ARP packets:
- Packet 1: ARP Request, MAC `aa:bb:cc:dd:ee:01`, src IP `10.0.0.1`, target IP `10.0.0.2`
- Packet 2: ARP Reply, MAC `aa:bb:cc:dd:ee:02`, src IP `10.0.0.2`, target IP `10.0.0.1`
- Packet 3: ARP Request, MAC `aa:bb:cc:dd:ee:01`, src IP `10.0.0.1`, target IP `10.0.0.5`
- Packet 4: ARP Request (gratuitous), MAC `aa:bb:cc:dd:ee:03`, src IP `10.0.0.3`, target IP `10.0.0.3`

**Expected raw extraction (4 dicts):**
- Row 1: `opcode=1`, `src_mac="aa:bb:cc:dd:ee:01"`, `src_ip="10.0.0.1"`, `dst_ip="10.0.0.2"`
- Row 2: `opcode=2`, `src_mac="aa:bb:cc:dd:ee:02"`, `src_ip="10.0.0.2"`, `dst_ip="10.0.0.1"`
- Row 3: `opcode=1`, `src_mac="aa:bb:cc:dd:ee:01"`, `src_ip="10.0.0.1"`, `dst_ip="10.0.0.5"`
- Row 4: `opcode=1`, `src_mac="aa:bb:cc:dd:ee:03"`, `src_ip="10.0.0.3"`, `dst_ip="10.0.0.3"`

**Verify:** JSON check — `extract_arp` returns exactly 4 dicts with correct field types and values.

### T-EXT-02: ICMP Extraction

**Pcap:** `test_icmp_basic.pcap` — 4 ICMP packets:
- Packet 1: Echo Request, seq=1, at t=0.0s
- Packet 2: Echo Reply, seq=1, at t=0.005s (5ms RTT)
- Packet 3: Echo Request, seq=2, at t=1.0s
- Packet 4: Echo Reply, seq=2, at t=1.050s (50ms RTT)

**Expected:** 4 dicts. Requests have `type=8`, replies have `type=0`. Seq numbers and timestamps are correct. `resp_in` on requests points to the corresponding reply frame number.

### T-EXT-03: TCP Extraction

**Pcap:** `test_tcp_basic.pcap` — A minimal TCP handshake (SYN, SYN-ACK, ACK) + 1 data packet + FIN:
- Packet 1: SYN (flags=0x0002), stream 0, `10.0.0.1:12345` → `10.0.0.2:80`
- Packet 2: SYN-ACK (flags=0x0012), stream 0
- Packet 3: ACK (flags=0x0010), stream 0
- Packet 4: ACK+PSH (flags=0x0018), stream 0
- Packet 5: FIN-ACK (flags=0x0011), stream 0

**Expected:** 5 dicts. All in `stream=0`. Flags are parsed as hex strings. `tcp.analysis.retransmission` is `None` for all. `tcp.time_delta` is present and positive for packets 2-5.

### T-EXT-04: DNS Extraction

**Pcap:** `test_dns_basic.pcap` — 2 DNS query/response pairs:
- Packet 1: DNS query, id=0x1234, qname=`example.com`
- Packet 2: DNS response, id=0x1234, rcode=0 (NOERROR), dns.time=0.015s
- Packet 3: DNS query, id=0x5678, qname=`test.org`
- Packet 4: DNS response, id=0x5678, rcode=3 (NXDOMAIN), dns.time=0.030s

**Expected:** 4 dicts. Queries have `flags_response=0`, `dns_time=None`. Responses have `flags_response=1`, correct rcode, and `dns_time` as float.

### T-EXT-05: Capture Summary

**Pcap:** `test_summary.pcap` — 10 packets of mixed types spanning 5.0 seconds.

**Expected:** `{"file": "test_summary.pcap", "total_packets": 10, "duration_seconds": 5.0}` (duration approximately 5.0, allowing ±0.01s tolerance).

### T-EXT-06: Empty Protocol

**Pcap:** `test_tcp_only.pcap` — Contains only TCP packets, no ARP/ICMP/DNS.

**Expected:** `extract_arp()` returns `[]`. `extract_icmp()` returns `[]`. `extract_dns()` returns `[]`. `extract_tcp()` returns a non-empty list.

---

## Test Category 3: Semantic Reduction (Stage 3)

### Shared Helper

| ID | Scenario | Input | Expected |
|----|----------|-------|----------|
| T-STAT-01 | Normal list | `[1.0, 2.0, 3.0, 4.0, 100.0]` | `min=1.0, median=3.0, p95=100.0, max=100.0` |
| T-STAT-02 | Single value | `[5.0]` | `min=5.0, median=5.0, p95=5.0, max=5.0` |
| T-STAT-03 | Empty list | `[]` | `min=0, median=0, p95=0, max=0` |
| T-STAT-04 | Two values | `[10.0, 20.0]` | `min=10.0, median=15.0, p95=20.0, max=20.0` |

### ARP Reduction

| ID | Scenario | Pcap | Expected Semantic JSON |
|----|----------|------|----------------------|
| T-ARP-01 | Balanced requests and replies | `test_arp_basic.pcap` (from T-EXT-01) | `total_requests=3, total_replies=1, unanswered_requests=[{"ip": "10.0.0.5", "count": 1}], gratuitous_arp_count=1`. Note: gratuitous ARP (packet 4) is counted in `total_requests` (opcode=1) and in `gratuitous_arp_count`, but is **excluded** from the unanswered check since gratuitous ARPs are announcements that do not expect a reply. |
| T-ARP-02 | All requests answered | Pcap with 5 ARP requests each followed by a reply | `total_requests=5, total_replies=5, unanswered_requests=[], gratuitous_arp_count=0` |
| T-ARP-03 | No ARP traffic | `test_tcp_only.pcap` | ARP section omitted from Semantic JSON entirely |
| T-ARP-04 | Multiple unanswered for same IP | 4 requests for `10.0.0.99`, no replies | `unanswered_requests=[{"ip": "10.0.0.99", "count": 4}]` |
| T-ARP-05 | Only gratuitous ARP | 3 packets where `src_ip == dst_ip` | `total_requests=3, total_replies=0, unanswered_requests=[], gratuitous_arp_count=3`. Gratuitous ARPs are excluded from the unanswered check — `unanswered_requests` must be empty even though there are no replies. |

### ICMP Reduction

| ID | Scenario | Pcap | Expected Semantic JSON |
|----|----------|------|----------------------|
| T-ICMP-01 | All pings answered, uniform RTT | 10 echo req/reply pairs, all ~5ms RTT | `echo_pairs_matched=10, echo_unmatched=0, rtt_ms.median≈5.0, anomalies=[]` |
| T-ICMP-02 | Some pings unanswered | 10 requests, only 7 replies | `echo_pairs_matched=7, echo_unmatched=3` |
| T-ICMP-03 | One high-RTT anomaly | 9 pairs at ~5ms, 1 pair at 500ms | `anomalies` list has 1 entry with `rtt_ms=500.0` (500 > 2x median of ~5) |
| T-ICMP-04 | Multiple anomalies | 8 pairs at exactly 5ms, 2 pairs at exactly 100ms | Sorted RTTs: [5,5,5,5,5,5,5,5,100,100]. Median=5.0. Threshold=10.0. Both 100ms pairs appear in `anomalies` (100 > 2×5). |
| T-ICMP-05 | All high RTT (no anomaly) | 5 pairs all at ~200ms | `rtt_ms.median≈200, anomalies=[]` (none exceed 2x median since they're all similar) |
| T-ICMP-06 | No ICMP traffic | TCP-only pcap | ICMP section omitted from Semantic JSON |
| T-ICMP-07 | RTT unit conversion | 1 pair with 0.025s RTT | `rtt_ms` values in milliseconds: `min=25.0, median=25.0` |

### TCP Reduction

| ID | Scenario | Pcap | Expected Semantic JSON |
|----|----------|------|----------------------|
| T-TCP-01 | Clean handshake, no issues | 1 stream: SYN, SYN-ACK, ACK, data, FIN | `streams_total=1, retransmissions_total=0, rst_count=0, streams_with_issues=[]` |
| T-TCP-02 | Retransmissions present | 1 stream with 3 retransmissions injected | `retransmissions_total=3, streams_with_issues` has 1 entry with `retransmissions=3` and `sample_frames` listing the 3 retransmission frame numbers |
| T-TCP-03 | RST connection reset | 1 stream ending with RST instead of FIN | `rst_count=1, streams_with_issues` has 1 entry with `rst=true` and `sample_frames` containing the RST frame number |
| T-TCP-04 | High inter-packet delta | 2 streams, each with 20 packets: stream 0 has all 1ms deltas; stream 1 has 19 packets at 1ms + 1 packet at 500ms. Overall median delta across all 40 packets ≈ 1ms. Stream 1 p95 delta ≈ 500ms (> 2×1ms). | Stream 1 appears in `streams_with_issues`. Stream 0 does not. |
| T-TCP-05 | Multiple streams, mixed health | 3 streams: stream 0 clean, stream 1 has retransmissions, stream 2 has RST | `streams_total=3, streams_with_issues` has exactly 2 entries (streams 1 and 2) |
| T-TCP-06 | sample_frames capped at 5 | 1 stream with 20 retransmissions | `streams_with_issues[0].sample_frames` has exactly 5 entries |
| T-TCP-07 | Delta unit conversion | Stream with 0.1s inter-packet time | `delta_ms.median` ≈ 100.0 (milliseconds) |
| T-TCP-08 | Flag bitmask parsing | Packets with SYN (0x0002), SYN-ACK (0x0012), RST (0x0004), FIN (0x0001) | Per-stream flag counts are correct: SYN=1, ACK from SYN-ACK counted, RST=1, FIN=1 |
| T-TCP-09 | No TCP traffic | ICMP-only pcap | TCP section omitted from Semantic JSON |

### DNS Reduction

| ID | Scenario | Pcap | Expected Semantic JSON |
|----|----------|------|----------------------|
| T-DNS-01 | All queries answered, NOERROR | 10 query/response pairs, all rcode=0, ~15ms | `queries_total=10, responses_total=10, unanswered_queries=0, rcode_distribution={"NOERROR": 10}, slow_queries=[]` |
| T-DNS-02 | Unanswered queries | 10 queries, 7 responses | `queries_total=10, responses_total=7, unanswered_queries=3` |
| T-DNS-03 | NXDOMAIN responses | 8 NOERROR + 2 NXDOMAIN | `rcode_distribution={"NOERROR": 8, "NXDOMAIN": 2}` |
| T-DNS-04 | SERVFAIL responses | 9 NOERROR + 1 SERVFAIL | `rcode_distribution={"NOERROR": 9, "SERVFAIL": 1}` |
| T-DNS-05 | Slow query anomaly | 9 responses at ~15ms, 1 response at 500ms | `slow_queries` has 1 entry with `latency_ms=500.0` and the query name |
| T-DNS-06 | Multiple slow queries | 8 responses at ~15ms, 2 at 200ms | Both 200ms queries in `slow_queries` (200 > 2x15) |
| T-DNS-07 | All queries slow (no anomaly) | 5 responses all at ~300ms | `latency_ms.median≈300, slow_queries=[]` (none exceed 2x median) |
| T-DNS-08 | Latency unit conversion | Response with dns.time=0.045s | `latency_ms` shows 45.0 |
| T-DNS-09 | No DNS traffic | TCP-only pcap | DNS section omitted from Semantic JSON |
| T-DNS-10 | Mixed rcodes | 5 NOERROR + 3 NXDOMAIN + 1 SERVFAIL + 1 REFUSED | `rcode_distribution={"NOERROR": 5, "NXDOMAIN": 3, "SERVFAIL": 1, "REFUSED": 1}` |

---

## Test Category 4: Semantic JSON Assembly

| ID | Scenario | Pcap | Expected |
|----|----------|------|----------|
| T-SEM-01 | All protocols present | Pcap with ARP + ICMP + TCP + DNS traffic | `protocols_present=["ARP", "ICMP", "TCP", "DNS"]`, all four protocol sections present |
| T-SEM-02 | Single protocol only | TCP-only pcap | `protocols_present=["TCP"]`, only `capture_summary` and `tcp` sections in JSON |
| T-SEM-03 | Two protocols | ICMP + DNS pcap | `protocols_present=["ICMP", "DNS"]`, no `arp` or `tcp` sections |
| T-SEM-04 | No recognized protocols | Pcap with only UDP (non-DNS) traffic | `protocols_present=[]`, only `capture_summary` present. JSON is valid. |
| T-SEM-05 | JSON is valid | Any pcap | Output file is valid JSON (`json.loads()` succeeds) |
| T-SEM-06 | JSON indentation | Any pcap | Output file uses 2-space indentation (human-readable) |

---

## Test Category 5: AI Prompt and Report (Stage 4)

### Prompt Construction

| ID | Scenario | Verification |
|----|----------|-------------|
| T-PRM-01 | Prompt contains Semantic JSON | Intercept `build_prompt()` output — verify it contains `--- BEGIN SEMANTIC JSON ---` and `--- END SEMANTIC JSON ---` delimiters with the JSON between them |
| T-PRM-02 | Prompt requests three sections | Prompt text contains `## Executive Summary`, `## Anomaly Table`, `## Remediation` |
| T-PRM-03 | No payload data in prompt | Prompt string contains no raw packet bytes, no hex payload dumps, no application-layer data. Only metadata and statistics. |

### Report Structure

| ID | Scenario | Pcap | Expected |
|----|----------|------|----------|
| T-RPT-01 | Report has three sections | Any pcap with anomalies | Report contains `## Executive Summary`, `## Anomaly Table`, `## Remediation` headings |
| T-RPT-02 | Anomaly table is a Markdown table | Any pcap with anomalies | Table has header row `Protocol | Issue | Detail | Frame(s)` with separator row |
| T-RPT-03 | Healthy capture report | Clean pcap (no anomalies) | Executive Summary mentions healthy/no issues. Anomaly table has "No anomalies detected" row. Remediation says "No action required." |
| T-RPT-04 | Report references frame numbers | Pcap with TCP retransmissions | Anomaly table rows reference specific frame numbers from the Semantic JSON `sample_frames` |
| T-RPT-05 | Report references IP addresses | Pcap with problematic TCP stream | Remediation or anomaly table mentions the src/dst IP from `streams_with_issues` |

---

## Test Category 6: Output Files

| ID | Scenario | Expected |
|----|----------|----------|
| T-OUT-01 | Semantic JSON file created | `<stem>_semantic.json` exists in same directory as input pcap |
| T-OUT-02 | Report file created | `<stem>_forensic_report.md` exists in same directory as input pcap |
| T-OUT-03 | Naming from `.pcap` | Input `capture.pcap` → `capture_semantic.json` + `capture_forensic_report.md` |
| T-OUT-04 | Naming from `.pcapng` | Input `capture.pcapng` → `capture_semantic.json` + `capture_forensic_report.md` |
| T-OUT-05 | Overwrite existing files | Run tool twice on same pcap. Second run overwrites files without error. |
| T-OUT-06 | Console shows file paths | Console output includes the full path of both saved files |

---

## Test Category 7: Error Handling

| ID | Scenario | Expected |
|----|----------|----------|
| T-ERR-01 | Corrupt pcap file | Create a file with `.pcap` extension but random bytes inside. Tool prints tshark's stderr message, exits 1. |
| T-ERR-02 | Invalid API key | Set `GEMINI_API_KEY` to `"invalid"`. Stages 1-3 succeed (Semantic JSON is saved). Stage 4 prints a user-friendly API error (no key in message), exits 1. |
| T-ERR-03 | No tracebacks shown | For any error case (V-01 through V-08, T-ERR-01, T-ERR-02), verify that no Python traceback is printed to stdout or stderr. Only user-friendly messages. |
| T-ERR-04 | Semantic JSON saved before AI failure | Set invalid API key, run tool. Verify `_semantic.json` exists on disk even though report generation failed. |
| T-ERR-05 | tshark permission error mid-run | Start a valid run, but make the pcap unreadable after validation passes (e.g., `chmod 000` between stage 1 and stage 2 via a race condition or a FIFO). Tool should print tshark's stderr and exit 1 — not crash with a traceback. |

---

## Test Category 8: Anomaly Detection (Comprehensive)

These tests use purpose-built pcaps that combine multiple anomaly types to verify the tool detects and reports all of them. These are the most important tests — they validate the tool's core diagnostic value.

### T-ANOM-01: Multi-Anomaly Capture

**Pcap:** `test_multi_anomaly.pcap` — combines:
- 5 ARP requests for `10.0.0.99` with no replies (unanswered)
- 2 gratuitous ARP packets
- 20 ICMP echo pairs at ~5ms, 2 pairs at 500ms (high RTT)
- 3 ICMP requests with no reply (unanswered)
- 2 TCP streams: stream 0 clean, stream 1 has 8 retransmissions + RST
- 30 DNS query/response pairs: 25 NOERROR at ~15ms, 3 NXDOMAIN, 2 at 400ms (slow)
- 2 DNS queries with no response (unanswered)

**Expected Semantic JSON:**

| Section | Field | Expected Value |
|---------|-------|----------------|
| `arp` | `total_requests` | 7 (5 normal + 2 gratuitous) |
| `arp` | `total_replies` | 0 |
| `arp` | `unanswered_requests` | `[{"ip": "10.0.0.99", "count": 5}]` |
| `arp` | `gratuitous_arp_count` | 2 |
| `icmp` | `echo_pairs_matched` | 22 |
| `icmp` | `echo_unmatched` | 3 |
| `icmp` | `anomalies` length | 2 (the 500ms pairs) |
| `tcp` | `streams_total` | 2 |
| `tcp` | `retransmissions_total` | 8 |
| `tcp` | `rst_count` | 1 |
| `tcp` | `streams_with_issues` length | 1 (stream 1 only) |
| `tcp` | `streams_with_issues[0].sample_frames` length | 5 (capped from 8 retrans + 1 RST) |
| `dns` | `queries_total` | 32 |
| `dns` | `responses_total` | 30 |
| `dns` | `unanswered_queries` | 2 |
| `dns` | `rcode_distribution` | `{"NOERROR": 27, "NXDOMAIN": 3}` |
| `dns` | `slow_queries` length | 2 (the 400ms queries) |

**Expected Report:** All six anomaly types (ARP unanswered, ICMP high RTT, ICMP unanswered, TCP retrans+RST, DNS NXDOMAIN, DNS slow) should appear in the anomaly table. Remediation should include actionable steps.

### T-ANOM-02: Healthy Capture (No Anomalies)

**Pcap:** `test_healthy.pcap` — all clean traffic:
- 5 ARP request/reply pairs (all answered)
- 10 ICMP echo pairs at uniform ~5ms
- 1 TCP stream with clean handshake, data, FIN (no retransmissions)
- 10 DNS query/response pairs, all NOERROR at ~15ms

**Expected Semantic JSON:**
- `arp.unanswered_requests=[]`, `gratuitous_arp_count=0`
- `icmp.echo_unmatched=0`, `anomalies=[]`
- `tcp.retransmissions_total=0`, `rst_count=0`, `streams_with_issues=[]`
- `dns.unanswered_queries=0`, `rcode_distribution={"NOERROR": 10}`, `slow_queries=[]`

**Expected Report:** Executive Summary states healthy. Anomaly table has single "No anomalies detected" row. Remediation: "No action required."

### T-ANOM-03: ARP Storm

**Pcap:** `test_arp_storm.pcap` — 100 ARP requests for 20 different IPs, 0 replies.

**Expected:** `unanswered_requests` has 20 entries grouped by IP. Report should flag widespread ARP resolution failure.

### T-ANOM-04: ICMP Blackhole

**Pcap:** `test_icmp_blackhole.pcap` — 50 ICMP echo requests, 0 replies.

**Expected:** `echo_pairs_matched=0, echo_unmatched=50, rtt_ms` stats all zero, `anomalies=[]` (no RTTs to be anomalous). Report should flag complete ICMP reachability failure.

### T-ANOM-05: TCP Retransmission Storm

**Pcap:** `test_tcp_retrans_storm.pcap` — 1 stream with 50 retransmissions.

**Expected:** `retransmissions_total=50`, `streams_with_issues` has 1 entry, `sample_frames` has exactly 5 entries (capped). Report should flag severe retransmission issue.

### T-ANOM-06: TCP RST Only (Connection Refused)

**Pcap:** `test_tcp_rst.pcap` — SYN sent, RST-ACK received (connection refused pattern).

**Expected:** `rst_count=1`, `streams_with_issues` has 1 entry with `rst=true`. Report should flag connection refusal.

### T-ANOM-07: DNS Total Failure

**Pcap:** `test_dns_failure.pcap` — 20 DNS queries, all responses are SERVFAIL.

**Expected:** `rcode_distribution={"SERVFAIL": 20}`, no NOERROR entries. Report should flag DNS server failure.

### T-ANOM-08: DNS Exfiltration Pattern (Many NXDOMAIN)

**Pcap:** `test_dns_nxdomain.pcap` — 50 queries for random subdomains of `evil.com`, all return NXDOMAIN.

**Expected:** `rcode_distribution={"NXDOMAIN": 50}`. Report should flag suspicious NXDOMAIN volume.

### T-ANOM-09: Mixed TCP Health Across Streams

**Pcap:** `test_tcp_mixed.pcap` — 5 streams:
- Stream 0: clean
- Stream 1: 3 retransmissions
- Stream 2: ends with RST
- Stream 3: clean
- Stream 4: high inter-packet deltas (p95 > 2x overall median)

**Expected:** `streams_total=5, streams_with_issues` has exactly 3 entries (streams 1, 2, 4). Streams 0 and 3 are excluded.

### T-ANOM-10: Single Anomalous ICMP Among Many

**Pcap:** `test_icmp_one_slow.pcap` — 100 echo pairs at ~2ms, 1 pair at 1000ms.

**Expected:** `anomalies` has exactly 1 entry. `rtt_ms.median≈2.0`, `rtt_ms.max=1000.0`. Verifies that a single outlier is detected among many normal packets.

---

## Test Category 9: Edge Cases

| ID | Scenario | Pcap | Expected |
|----|----------|------|----------|
| T-EDGE-01 | Empty pcap (0 packets) | `test_empty.pcap` — valid pcap header, no packets | `capture_summary.total_packets=0, duration_seconds=0`. No protocol sections. AI reports "no anomalies." |
| T-EDGE-02 | Single packet | `test_single.pcap` — 1 TCP SYN packet | `total_packets=1`. TCP section has `streams_total=1, streams_with_issues=[]` (one SYN alone isn't anomalous). |
| T-EDGE-03 | Only unrecognized protocols | `test_udp_only.pcap` — UDP packets (non-DNS, port != 53) | All extractors return `[]`. `protocols_present=[]`. Only `capture_summary` in JSON. |
| T-EDGE-04 | DNS multi-value field | DNS response with multiple qnames in one packet | Extractor takes first value only. JSON has one `qry.name` per row. |
| T-EDGE-05 | TCP flags edge: SYN-ACK-RST simultaneously | Packet with flags=0x0016 (SYN+ACK+RST) | Bitmask correctly identifies all three flags set. |
| T-EDGE-06 | Very long DNS name | Query for a 253-character domain name | Extracted correctly. JSON contains full name. No truncation. |
| T-EDGE-07 | Zero-delta TCP packets | Two TCP packets with identical timestamps (delta=0.0) | `delta_ms.min=0.0`. No crash or division-by-zero. |
| T-EDGE-08 | ICMP non-echo types | Pcap with ICMP type=3 (Destination Unreachable) + type=11 (Time Exceeded) alongside echo req/reply | Non-echo types are extracted but ignored by `reduce_icmp` (only type 0 and 8 are processed). Counts not affected. |
| T-EDGE-09 | pcapng format | Valid `.pcapng` file with mixed traffic | Tool processes it identically to `.pcap`. Same outputs. |

---

## Test Category 10: Privacy

| ID | Scenario | Verification |
|----|----------|-------------|
| T-PRIV-01 | No HTTP payloads in Semantic JSON | Pcap containing HTTP GET/POST with body content (e.g., `"password=secret123"`). Open `_semantic.json` — verify no HTTP body text, URLs with query params, or request/response content appears. |
| T-PRIV-02 | No FTP/SMTP credentials in Semantic JSON | Pcap containing FTP login (`USER admin / PASS secret`) and SMTP `AUTH` exchange. Verify no credentials appear in `_semantic.json`. |
| T-PRIV-03 | No TLS certificate details in Semantic JSON | Pcap with TLS handshake (Client Hello, Server Hello, certificates). Verify no certificate subjects, SNI values, or cipher details appear in `_semantic.json`. |
| T-PRIV-04 | No payloads in AI prompt | Intercept `build_prompt()` output (add a temporary print/write). Verify the prompt contains only the Semantic JSON (metadata and stats), no raw packet bytes or application data. |
| T-PRIV-05 | tshark commands request no payload fields | Code review: every tshark invocation uses only the fields listed in design.md. None include payload-bearing fields like `data`, `http.file_data`, `tcp.payload`, `tls.handshake.certificate`, etc. |
| T-PRIV-06 | DNS query names are metadata, not payload | Acknowledged: DNS query names (e.g., `api.example.com`) ARE included in the Semantic JSON as metadata for diagnostic purposes. This is by design — they are protocol headers, not application payload. Verify this is limited to `dns.qry.name` and does not include DNS response record data (A records, CNAME targets, TXT records). |

---

## Test Category 11: Data Integrity

| ID | Scenario | Verification |
|----|----------|-------------|
| T-INT-01 | JSON roundtrip | Load the saved `_semantic.json` with `json.loads()`. Verify every field and value matches the expected output for the test pcap. No data is lost or corrupted during serialization. |
| T-INT-02 | Saved JSON matches AI input | Intercept the Semantic JSON dict passed to `build_prompt()`. Also load the saved `_semantic.json`. Verify they are identical (`==`). The AI must analyze the exact same data that's saved to disk. |
| T-INT-03 | Duration consistency | Pcap with first packet at t=1000.0 and last packet at t=1005.0. Verify `duration_seconds=5.0` (not 1005.0, not based on wall-clock time). |
| T-INT-04 | Packet counts are accurate | `test_multi_anomaly.pcap`: manually count total packets in the pcap (using `tshark -r <pcap> | wc -l`). Verify `capture_summary.total_packets` matches. |
| T-INT-05 | Anomaly frame numbers exist | For every frame number referenced in `anomalies`, `slow_queries`, and `sample_frames` in the Semantic JSON, verify it's a valid frame number in the pcap (within range 1 to `total_packets`). |
| T-INT-06 | Stats math is correct | For T-ANOM-01's ICMP section: manually compute min/median/p95/max from the 22 RTT values. Verify `rtt_ms` stats in the JSON match within ±0.1ms tolerance. |

---

## Test Category 12: Security

| ID | Scenario | Verification |
|----|----------|-------------|
| T-SEC-01 | Command injection via filename | Create a valid pcap named `` test`whoami`.pcap `` (with backticks). Run tool. Verify tshark is called with list args (`subprocess.run([...])` not `shell=True`). The filename must be passed as a single argument, not interpolated into a shell string. Tool processes the file or fails with a clean file-not-found — never executes the injected command. |
| T-SEC-02 | Semicolon in filename | Create a valid pcap named `test;rm -rf /.pcap`. Run tool. Verify no shell command is executed — only a file-not-found or successful processing. |
| T-SEC-03 | Path traversal in filename | Run `python pcap_forensics.py ../../../etc/passwd`. Verify tool rejects it (wrong extension), exits 1. Does not read or expose `/etc/passwd` contents. |
| T-SEC-04 | API key not in error output | Set `GEMINI_API_KEY` to `"sk-test-secret-12345"`. Trigger API failure. Verify the string `sk-test-secret-12345` does NOT appear in stdout, stderr, `_semantic.json`, or `_forensic_report.md`. |
| T-SEC-05 | API key not in saved files | Run tool successfully. Verify `GEMINI_API_KEY` value does not appear anywhere in `_semantic.json` or `_forensic_report.md`. |
| T-SEC-06 | Subprocess uses list args | Code review: every `subprocess.run()` or `subprocess.Popen()` call uses a list of arguments (not a string). `shell=True` is never used. |

---

## Test Category 12: Token Efficiency

Token counting method: Use the Gemini tokenizer API (`client.models.count_tokens(model="gemini-2.0-flash", contents=json_string)`) for exact counts. As a fallback, `len(json_string) / 4` provides a rough estimate (typically overestimates for JSON with short keys and numbers). Both methods should be recorded.

| ID | Scenario | Pcap | Verification |
|----|----------|------|-------------|
| T-TOK-01 | Small capture (<1MB) | ~1,000 packets, all 4 protocols, few anomalies | Token count of `_semantic.json` is well under 5,000 (expect ~500-1,500). |
| T-TOK-02 | Medium capture (~10MB, the requirement baseline) | ~100,000 packets across all protocols. Generate with: 50 ARP, 200 ICMP, 95,000 TCP across 50 streams (10 with issues), 4,750 DNS (50 slow). | Token count of `_semantic.json` must be < 5,000. This is the primary requirement validation. If it exceeds 5,000, the reduction strategies need tightening. |
| T-TOK-03 | Large capture with many anomalous streams | 200 TCP streams, 50 with retransmissions, 30 with RST. 500 DNS queries, 100 NXDOMAIN, 50 slow. | Verify `streams_with_issues` is bounded (50 entries × ~6 fields each). `slow_queries` is bounded. Token count must remain < 5,000. If not, a cap on `streams_with_issues` entries (e.g., top 20 by severity) may be needed — flag this as a design revision. |
| T-TOK-04 | Worst-case anomaly density | Every protocol has maximum anomalies: 50 unanswered ARP IPs, 100 ICMP anomalies, 100 streams with issues, 200 slow DNS queries. | Stress test: measure token count. If it exceeds 5,000, the reduction stage needs additional caps (e.g., top-N anomalies per protocol). Document the breaking point. |

---

## Synthetic Pcap Generation

All test pcaps are generated by `generate_test_pcaps.py` using `scapy`. The script structure:

```python
from scapy.all import *

def make_test_arp_basic():
    """T-EXT-01, T-ARP-01: 4 ARP packets with known fields."""
    ...
    wrpcap("test_pcaps/test_arp_basic.pcap", packets)

def make_test_multi_anomaly():
    """T-ANOM-01: Combined anomaly pcap."""
    ...
    wrpcap("test_pcaps/test_multi_anomaly.pcap", packets)

# ... one function per test pcap ...

if __name__ == "__main__":
    os.makedirs("test_pcaps", exist_ok=True)
    make_test_arp_basic()
    make_test_icmp_basic()
    make_test_tcp_basic()
    make_test_dns_basic()
    make_test_summary()
    make_test_tcp_only()
    make_test_multi_anomaly()
    make_test_healthy()
    make_test_arp_storm()
    make_test_icmp_blackhole()
    make_test_tcp_retrans_storm()
    make_test_tcp_rst()
    make_test_dns_failure()
    make_test_dns_nxdomain()
    make_test_tcp_mixed()
    make_test_icmp_one_slow()
    make_test_empty()
    make_test_single()
    make_test_udp_only()
    make_test_pcapng()
    make_test_http_payload()      # T-PRIV-01: HTTP with body content
    make_test_ftp_smtp_creds()    # T-PRIV-02: FTP/SMTP credentials
    make_test_tls_handshake()     # T-PRIV-03: TLS certificates
    make_test_worst_case_anomaly()  # T-TOK-04: maximum anomaly density
    print(f"Generated {len(os.listdir('test_pcaps'))} test pcap files.")
```

**Dependency:** `scapy` is needed only for test pcap generation, not for the tool itself. Install with `pip install scapy`.

---

## Test Execution Checklist

Run through these in order. Each row is a manual pass/fail.

| # | Test IDs | Category | Count | Pass/Fail |
|---|----------|----------|-------|-----------|
| 1 | V-01 through V-11 | Input Validation | 11 | |
| 2 | T-EXT-01 through T-EXT-06 | Extraction Correctness | 6 | |
| 3 | T-STAT-01 through T-STAT-04 | compute_stats | 4 | |
| 4 | T-ARP-01 through T-ARP-05 | ARP Reduction | 5 | |
| 5 | T-ICMP-01 through T-ICMP-07 | ICMP Reduction | 7 | |
| 6 | T-TCP-01 through T-TCP-09 | TCP Reduction | 9 | |
| 7 | T-DNS-01 through T-DNS-10 | DNS Reduction | 10 | |
| 8 | T-SEM-01 through T-SEM-06 | Semantic JSON Assembly | 6 | |
| 9 | T-PRM-01 through T-PRM-03 | Prompt Construction | 3 | |
| 10 | T-RPT-01 through T-RPT-05 | Report Structure | 5 | |
| 11 | T-OUT-01 through T-OUT-06 | Output Files | 6 | |
| 12 | T-ERR-01 through T-ERR-05 | Error Handling | 5 | |
| 13 | T-ANOM-01 through T-ANOM-10 | Anomaly Detection | 10 | |
| 14 | T-EDGE-01 through T-EDGE-09 | Edge Cases | 9 | |
| 15 | T-INT-01 through T-INT-06 | Data Integrity | 6 | |
| 16 | T-SEC-01 through T-SEC-06 | Security | 6 | |
| 17 | T-PRIV-01 through T-PRIV-06 | Privacy | 6 | |
| 18 | T-TOK-01 through T-TOK-04 | Token Efficiency | 4 | |

**Total: 118 test cases across 14 categories.**
