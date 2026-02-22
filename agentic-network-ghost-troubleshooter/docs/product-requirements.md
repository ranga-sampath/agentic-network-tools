Refined Product Requirements: Unified Ghost Agent CLI

1. Vision & Strategic Context
The Network Ghost Agent is an intent-driven investigation system for complex cloud networking. Having built the secure execution (Shell), cloud orchestration (Orchestrator), and protocol analysis (Forensic Engine) layers, we now require a central "Reasoning Loop." This loop serves as the project’s mission control, orchestrating these components to solve functional network failures.

2. Component Inventory (The Toolset)
The CLI acts as a manager for the following sibling modules:

Safe-Exec Shell (agentic-safety-shell): Executes all CLI-based diagnostics (ping, dig, mtr) through a mandatory HITL safety gate.

Cloud Orchestrator (agentic-cloud-orchestrator): Manages long-running Azure operations (packet captures, blob downloads) and provides asynchronous task tracking.

PCAP Forensic Engine (agentic-pcap-forensic-engine): Parses raw telemetry into Semantic JSON for evidence-based diagnosis.

3. Core Functional Use Cases
The agent's primary value is in resolving "Functional" (non-statistical) failures. See some examples below.

Reachability Analysis: Determining if a path is blocked by UDRs, VNet Peering issues, or NSG rules.

DNS Troubleshooting: Identifying resolution failures in private or hybrid DNS zones.

Service Availability: Diagnosing TCP-level failures (e.g., Connection Refused) between cloud-native tiers.

4. Unified User Experience (UX)
The Initial Handshake: Upon startup, the agent performs a "Self-Check": it detects the environment (M5 Mac vs. Azure), scans for orphaned tasks/resources from previous sessions, and offers a bulk-cleanup before accepting new intents.

The Reasoning Loop: The agent accepts a natural language complaint. It then develops a plan, executes tools, and processes feedback. If a command is denied by the user, the agent must acknowledge the constraint and attempt an alternative path.

Continuous Evidence Chain: The agent maintains a "Living Audit." Every output from a local dig and every finding from a remote .pcap is added to a persistent session state to build the final root-cause report.
