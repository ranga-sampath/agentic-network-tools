# Agentic Safety Shell 🛡️

**The Deterministic Guardrail for Autonomous Network Agents.**

The **Agentic Safety Shell** is a security-first middleware designed to sit between an AI Agent (the "Brain") and your infrastructure. It transforms a potentially volatile autonomous agent into a trusted, high-speed assistant by ensuring every action is governed by a strict safety protocol.

Unlike AI-based guardrails, this shell uses a **deterministic four-stage pipeline** to ensure that no mutative or catastrophic actions—such as deleting a resource or triggering a billing spike—occur without explicit human approval.

---

## 🚀 Key Features

* **Four-Tier Defense Model**: Uses a strict "default-deny" logic where any command not explicitly classified as `SAFE` is treated as `RISKY`.
* **Synchronous HITL Gate**: Blocks the agent pipeline completely for risky commands, requiring the user to Approve, Deny, or Modify the action.
* **Anti-Wall Filter**: Automatically truncates verbose CLI outputs (like massive Azure JSON arrays) to keep them within LLM token budgets.
* **Privacy First**: Regex-based redaction scans for API keys, bearer tokens, and passwords, ensuring secrets never reach the AI Brain or audit logs.
* **Append-Only Audit Trail**: Every command, its reasoning, and the user's decision are recorded in session-scoped JSONL files.

---

## 🛠️ The Four-Tier Defense Model

Every command must pass all four tiers to be classified as `SAFE`. Any single failure triggers the Human-in-the-Loop (HITL) gate.

| Tier | Mechanism | Target | Example |
| :--- | :--- | :--- | :--- |
| **0** | **Forbidden List** | Catastrophic commands (Blocked unconditionally) | `rm -rf /`, `mkfs` |
| **1** | **Allowlist** | Known safe diagnostic tools | `ping`, `traceroute`, `dig` |
| **2** | **Verb Rules** | Mutative Azure CLI actions | `list` (Safe) vs `delete` (Risky) |
| **3** | **Pattern Match** | Privilege escalation and shell evasion | `sudo`, `&&`, `$(...)` |

---

## 💻 Usage

### Independent Integration
The shell is a library consumed by the agent. It exposes a simple `execute` function.

```python
from safe_exec_shell import SafetyShell

# Initialize the shell
shell = SafetyShell()

# Execute with reasoning (Required for audit and HITL)
response = shell.execute(
    command="az network nsg rule list --resource-group prod-rg",
    reasoning="Inspecting firewall rules to see if port 443 is blocked"
)

print(response["status"]) # 'completed', 'denied', or 'error'
