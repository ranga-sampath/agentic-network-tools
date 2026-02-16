# Requirements: PCAP Forensic Engine

## User Persona
A Network Engineer/Admin troubleshooting connectivity, latency, or protocol-level failures.

## Functional Requirements
1. **Input**: Accept a standard `.pcap` or `.pcapng` file path.
2. **Automated Extraction**: Use `tshark` to programmatically extract metadata from the following protocols:
   - **Layer 2**: ARP (Requests vs. Replies).
   - **Layer 3**: ICMP (Echo Request/Reply sequence matching).
   - **Layer 4**: TCP (SYN/ACK/RST flags, Retransmissions, and Delta-times).
   - **Layer 7**: DNS (Queries vs. Responses, RCODEs, and Latency).
3. **Semantic Reduction**: Convert raw packet data into a "Semantic JSON" that groups repetitive events and highlights timing anomalies.
4. **AI Diagnosis**: Feed the Semantic JSON to an LLM (Claude) to generate a "Forensic Report."
5. **Output**: A Markdown report containing:
   - **Executive Summary**: What is the most likely root cause?
   - **Anomaly Table**: Specific packet numbers and timestamps for the "smoking guns."
   - **Remediation**: Suggested CLI commands or config changes.

## Non-Functional Requirements
- **Token Efficiency**: The final JSON sent to the AI must be < 5,000 tokens for a typical 10MB capture.
- **Privacy**: The tool must not send packet payloads (application data) to the AI.
