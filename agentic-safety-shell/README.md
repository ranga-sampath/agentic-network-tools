# Agentic Safety Shell 🛡️

**The Deterministic Guardrail for Autonomous Network Agents.**

The **Agentic Safety Shell** is a security-first middleware designed to sit between an AI Agent (the "Brain") and your infrastructure. It transforms a potentially volatile autonomous agent into a trusted, high-speed assistant by ensuring every action is governed by a strict safety protocol.

Unlike probabilistic AI-based guardrails, this shell uses a **deterministic four-stage pipeline** to ensure that no mutative or catastrophic actions occur without explicit human approval.

---

## 🚀 Why Network Engineers Need This

AI agents are brilliant at analysis but lack "physical" risk awareness. They might suggest `sudo ifconfig en0 down` to "refresh" a link, inadvertently taking your on-call engineer offline. The Safety Shell prevents this by:

* **Platform Translation**: If the AI suggests a Linux command (`ip addr`) on a Mac, the **HITL Gate** lets you **Modify** it to `ifconfig` on the fly, keeping the automation moving.
* **Zero-Trust Execution**: Commands containing `sudo` or mutative verbs like `delete` or `down` are blocked until you explicitly click **Approve**.
* **Token Efficiency**: Massive CLI outputs (e.g., a 1000-line `netstat`) are automatically truncated, saving 90% on token costs and preventing the LLM from getting "lost" in the data.
* **Privacy Guardrails**: Automatically redacts API keys, tokens, and sensitive IP patterns before they ever reach the AI's logs.


---

## 🛠️ The Four-Tier Defense Model

Every command must pass all four tiers to be classified as `SAFE`. Any single failure triggers the Human-in-the-Loop (HITL) gate.

| Tier | Mechanism | Target | Example |
| :--- | :--- | :--- | :--- |
| **0** | **Forbidden List** | Catastrophic commands (Blocked unconditionally) | `rm -rf /`, `mkfs` |
| **1** | **Allowlist** | Known safe diagnostic tools | `ping`, `traceroute`, `dig` |
| **2** | **Verb Rules** | Mutative actions | `list` (Safe) vs `delete` (Risky) |
| **3** | **Pattern Match** | Privilege escalation & Shell evasion | `sudo`, `&&`, `$(...)` |

---

## 💻 Agentic Demo

Witness the shell in action with a live AI Agent. This demo showcases the **Modify** flow (correcting platform errors) and the **Deny** flow (blocking dangerous probes).

### Setup
1. Create a `.env` file with your `GEMINI_API_KEY`.
2. Install dependencies: `uv add google-genai python-dotenv`.

### Run
```bash
uv run examples/ai_safety_demo.py
