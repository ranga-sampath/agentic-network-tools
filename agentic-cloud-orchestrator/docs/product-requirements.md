Product Requirements: Phase 2 — Cloud Visibility & Async Orchestration

1. Vision & Context
The Network Ghost Agent aims to be a fully autonomous investigator for complex network failures. Currently, the agent can parse static files (the Forensic Engine) and execute commands safely (the Shell).

Phase 2 is the critical bridge that allows the agent to move from a "Post-Mortem" analyzer to a "Live Responder." It introduces the ability to actively instrument an environment to capture "Ghost Packets" in real-time and handle the inherent latencies of cloud provider APIs without losing state or timing out.

2. The Problem
Observability Gap: Network experts currently have to manually configure, trigger, and download packet captures from Azure/GCP/AWS, which is time-consuming and prone to human error.

The "Cloud Latency" Wall: Cloud operations like az network watcher packet-capture create take 30–90 seconds. Standard agentic loops often "hang" or "double-tap" requests during these wait periods, leading to resource duplication or session timeouts.

Data Fragmentation: There is no automated pipeline that moves a live packet capture from a remote VM interface into a diagnostic AI brain in a single, secure motion.

3. User Experience (The Senior Engineer's View)
The engineer should be able to provide a high-level intent: "Trace the traffic between Web-VM-01 and the Redis-Cluster-Primary."

The Agent should then:

Handle the Wait: Acknowledge that the capture is starting and "stay alive" while Azure provisions the resources.

Auto-Instrument: Decide whether to use a VM Extension or a Sidecar container based on the target environment (VM vs. AKS).

Stream & Analyze: Automatically retrieve the results once the capture window closes and feed them directly into the existing forensic parser.

4. Key Functional Requirements
A. Asynchronous "Awareness" (The Waiting Room)
The system must support non-blocking operations. If a command takes more than a few seconds, the agent must be able to receive a "Pending" status and "Check Back" later.

The agent must maintain State Continuity. If the capture takes 10 minutes, the agent's "Brain" must remember why it started the capture and what it was looking for when the data finally arrives.

B. Automated Forensic Instrumentation (The Eyes)
Dual-End Placement: The agent must be capable of triggering captures at both the source and destination simultaneously to identify where packets are being dropped.

Transient Deployment: Support for "Forensic Sidecars"—short-lived containers or extensions that exist only for the duration of the investigation to minimize the security footprint.

C. Secure Pipeline Orchestration
Auto-Ingestion: Once a capture is complete, the system must automatically move the .pcap from cloud storage (e.g., Azure Blob) into the Agentic PCAP Forensic Engine.

Guardrail Integration: Every orchestration action (deploying a sidecar, starting a capture) must still pass through the Phase 1 Safe-Exec Shell for user approval.

5. Success Criteria
Zero-Timeout Operations: The agent can successfully complete a 5-minute Azure packet capture without the LLM session timing out.

End-to-End Automation: A user can go from "Intent" to "Semantic Packet Report" without manually touching the Azure Portal or CLI.

Resource Cleanliness: 100% of transient "Sidecars" or extensions are deleted automatically once the investigation is complete.
