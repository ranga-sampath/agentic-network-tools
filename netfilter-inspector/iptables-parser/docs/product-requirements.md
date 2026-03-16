# iptables Parser — Product Requirements Document

*Module 1 of the Netfilter Inspector*
*Reference: `concepts/vm-firewall-inspector-build-challenges.md`*

---

## 1. Overview

The iptables Parser is a standalone module that takes `iptables-save` output as its input and produces a structured, machine-readable representation of the complete IPv4 firewall ruleset. It answers the question a network engineer has always had to answer by eye: **what rules are present, in which table, in which chain, in what position, and what do they collectively mean?**

The module has no dependency on a running VM, a cloud provider, an SSH session, or any network connectivity. Its only input is text — specifically, the output of the `iptables-save` command, which is the de facto standard format for capturing, backing up, and restoring Linux IPv4 firewall state. It can parse that text from a file captured five minutes ago, from an incident artifact saved six months ago, or from a compliance snapshot stored in a repository.

This document covers the requirements for the parser module alone. It does not cover ip6tables, nftables, the Netfilter Inspector as a whole, Azure integration, drift comparison, or any other module in the Netfilter Inspector system.

---

## 2. The Problem This Module Solves

The `iptables-save` format is the universal currency of Linux IPv4 firewall state. It is produced by backup scripts, incident response procedures, compliance captures, Ansible playbooks, change management workflows, and sysadmins running a single command before making a firewall change. It is the closest thing Linux networking has to a structured firewall policy artifact.

Despite this ubiquity, `iptables-save` output is raw text — designed for `iptables-restore` to consume, not for a human or a downstream tool to analyse. The format is deterministic and parseable, but no widely available, purpose-built tool converts it to structured data for forensic and diagnostic use.

The consequences for a network engineer investigating a cloud incident:

- Determining whether a specific port is blocked in the INPUT chain requires reading through potentially hundreds of rules, mentally evaluating each against the port, considering chain order (first match wins), accounting for negated match criteria (e.g., a rule that matches everything *except* a given source address), and following RETURN targets across user-defined chains that alter traversal order.
- Comparing the firewall state before and after a change window requires a text diff against two `iptables-save` files. If the capture was made with `--counters`, every rule line that had any traffic since the last capture shows a counter difference — potentially hundreds of false positives in the diff output that obscure the actual rule changes.
- Answering "which chains have a default policy of DROP?" requires reading the chain definition lines at the top of each table block and mentally noting the policy for each. On a Kubernetes node with dozens of custom chains, this is a multi-minute manual task.
- Producing a structured artifact for an incident report or compliance ticket requires copying raw text into a ticket — unqueryable, un-diffable, and impractical to read six months later.

The iptables Parser eliminates all of these manual steps by doing the analysis once and producing a structured output that every downstream consumer — a human, a diff engine, a compliance tool, a Ghost Agent investigation chain — can query directly.

---

## 3. Standalone Value — The Case for Use as an Independent Tool

The iptables Parser has strong value entirely independent of the Netfilter Inspector, Ghost Agent, or any other tool in the stack. The case rests on one fact: **`iptables-save` output already exists in large quantities in every organisation that operates Linux VMs, and currently no accessible tool converts it to structured, queryable data for forensic and diagnostic use.**

### The existing corpus

Engineers, automation scripts, and operations procedures continuously produce `iptables-save` output in at least six contexts:

1. **Pre-change snapshots** — a diligent sysadmin or a change management script runs `iptables-save > rules.v4.pre_change` before modifying a firewall. This is standard practice.
2. **Incident response captures** — when a network fault is under investigation, capturing the firewall state is one of the first steps. The capture is typically `iptables-save` piped to a file.
3. **Compliance audit artifacts** — security frameworks (CIS, PCI-DSS, SOC 2) require evidence of firewall state at specific points in time. These are stored as `iptables-save` output in audit folders or version control.
4. **Backup and persistence scripts** — `/etc/iptables/rules.v4` (Debian/Ubuntu) and `/etc/sysconfig/iptables` (RHEL/CentOS) are the standard paths for firewall persistence across reboots, populated by `iptables-save`. These files are backed up and versioned.
5. **Version control** — infrastructure-as-code pipelines that manage firewall state via scripts rather than management tools like firewalld commit `iptables-save` output to git as the authoritative record of firewall configuration.
6. **Deployment records** — Ansible playbooks and Chef/Puppet runs that configure firewall rules often capture the post-deployment state as `iptables-save` output and store it as a run artifact.

Every one of these contexts produces a file that a network engineer today must read manually as raw text. The parser converts the entire existing corpus into queryable structured data without requiring any new data collection.

### Specific use cases that have standalone value

**Offline incident reconstruction.** An incident occurred six months ago. The post-incident review needs to answer: was port 8443 blocked at the time? The `iptables-save` from the incident capture is available. Today, answering this requires reading through the raw file and manually evaluating rules in chain order, accounting for negations and chain default policy. With the parser, it is a structured query against the parsed output.

**Offline change window verification.** Pre-change and post-change `iptables-save` captures exist. A structural diff of the two parsed rulesets shows exactly which rules were added, removed, or repositioned — without the counter-change false positives that a raw text diff produces. This is immediately useful to any engineer who has tried to text-diff two `iptables-save` files and found the output dominated by packet counter changes that mean nothing.

**Fleet consistency audit from collected artifacts.** A fleet of twenty VMs had their firewall state captured last night by an automation script. The parser processes all twenty files and the results are compared against a reference policy. Any VM whose parsed ruleset deviates is flagged. Today this requires twenty manual file inspections.

**Compliance evidence generation.** The parsed output — a structured JSON document with every rule, its table, chain, position, target, and match criteria explicitly recorded — is a far more useful compliance artifact than the raw `iptables-save` text. It is auditable, queryable, and self-describing. A compliance auditor can read a structured JSON record without knowing the `iptables-save` format.

**Answering "what is this firewall actually doing?"** When a VM is inherited, when a new team takes over a project, or when an engineer is asked to review a security posture they did not build, the parser provides an immediate structured summary: chain default policies, all chains with DROP rules, all conntrack/state rules and their positions, all active NAT translations, all user-defined chains and their entry points. This takes thirty seconds with the parser; it takes ten to thirty minutes of careful manual reading without it.

### Why a senior network engineer reaches for this over alternatives

The engineer's alternative today is one of three things: reading the raw file, using `grep` with port numbers, or piping `iptables-save` through ad-hoc shell commands. Each of these:

- Does not account for chain default policies — a `grep` for port 8443 finds a matching ACCEPT rule but misses a broad DROP rule at an earlier position in the same chain that fires first
- Does not account for negated match criteria — a rule with `! -s 10.0.0.0/8` matches everything *except* that prefix; grep for a source IP misses this class entirely
- Does not account for rule ordering — grep returns every rule mentioning the port, not the first matching rule, which is the only one that matters
- Does not follow RETURN targets in user-defined chains that alter traversal order
- Produces no persistent artifact for the investigation record

The parser handles all of these correctly and produces output a downstream tool or investigation chain can reason about without requiring iptables expertise.

---

## 4. Target User

**Primary:** Senior network engineer or cloud infrastructure engineer investigating a connectivity fault, verifying a change window, or conducting a firewall compliance audit on Linux VMs in Azure (or any cloud environment).

**Secondary:** An AI-assisted investigation agent (Ghost Agent or equivalent) that receives structured rule output and reasons about it as part of a broader RCA chain.

The primary user knows iptables well. They understand the difference between a DROP target and a REJECT target, between the filter table and the nat table, between chain default policy and rule targets. They do not need the parser to explain iptables to them — they need it to eliminate the manual reading that currently occupies their time during an incident.

---

## 5. What the Module Does

The module accepts `iptables-save` text as input and produces a structured representation of the complete IPv4 firewall ruleset captured in that text. Specifically:

### 5.1 Table and chain structure

For each table present in the input (`filter`, `nat`, `mangle`, `raw`, `security`):
- Table name
- List of chains defined in that table, each with:
  - Chain name
  - Type: `builtin` or `user-defined`
  - Default policy: `ACCEPT` or `DROP` for built-in chains; `null` for user-defined chains (user-defined chains have no default policy — a packet that reaches the end of a user-defined chain without matching any rule returns to the calling chain and continues from the rule after the jump)
  - Counter values for the default policy (packets and bytes that reached the end of the chain without matching any rule). **Chain policy counters are always present in valid `iptables-save` format** — they appear in the chain header line (`:INPUT DROP [0:0]`) regardless of whether `--counters` was used. These are distinct from per-rule counter prefixes, which only appear with `--counters`. A chain header with `[0:0]` in a non-`--counters` capture means zero packets reached the default policy, not that counters are absent.

Chains with no rules (only a policy line, common in the mangle and raw tables on standard VMs) are included in the output with an empty `rules` list. An empty chain is a valid and distinct state from a missing chain.

### 5.2 Per-rule structured record

For every rule in the input, in the exact order they appear in the `iptables-save` output for each chain. Position is determined entirely by this order — position 1 is the first rule line for that chain in the input and is the first rule evaluated for any packet entering the chain. There is no explicit position field in `iptables-save` format; position is assigned by the parser based on order.

| Field | Content |
|-------|---------|
| `table` | Table the rule belongs to (`filter`, `nat`, `mangle`, `raw`, `security`) |
| `chain` | Chain the rule appends to |
| `position` | 1-based position within the chain; position 1 is evaluated first |
| `protocol` | Protocol matched. Common named values: `tcp`, `udp`, `icmp`, `all`. Other named protocols as output by iptables-save (e.g., `esp`, `ah`, `gre`) are preserved verbatim. Numeric protocol numbers (e.g., `50` for ESP) are preserved as strings. `null` if no `-p` flag is present in the rule (matches all protocols). Do not normalise named protocols to numbers or vice versa — preserve the value exactly as it appears in the input. |
| `source` | Source IP or CIDR; `null` if not specified (matches any source) |
| `source_negated` | Boolean: `true` if the source match is negated (`! -s`) |
| `destination` | Destination IP or CIDR; `null` if not specified (matches any destination) |
| `destination_negated` | Boolean: `true` if the destination match is negated (`! -d`) |
| `in_interface` | Inbound interface name; `null` if not specified |
| `in_interface_negated` | Boolean: `true` if the inbound interface match is negated (`! -i`) |
| `out_interface` | Outbound interface name; `null` if not specified |
| `out_interface_negated` | Boolean: `true` if the outbound interface match is negated (`! -o`) |
| `dst_port` | Destination port or port range (e.g., `22`, `8080:8090`) from `-p tcp/udp --dport`; `null` if not specified or if `multiport` extension is used instead |
| `dst_port_negated` | Boolean: `true` if the destination port match is negated |
| `src_port` | Source port or port range from `-p tcp/udp --sport`; `null` if not specified or if `multiport` extension is used instead |
| `src_port_negated` | Boolean: `true` if the source port match is negated |
| `target` | Rule target: `ACCEPT`, `DROP`, `REJECT`, `LOG`, `RETURN`, `MASQUERADE`, `SNAT`, `DNAT`, `MARK`, `NFQUEUE`, `NFLOG`, or a user-defined chain name |
| `target_params` | Structured parameters for the target, if any (see 5.3); `null` for targets with no parameters |
| `target_stops_chain_traversal` | Whether this target stops traversal of the current chain for the matching packet. See note below. |
| `match_extensions` | Structured representation of match extension modules present in the rule (see 5.3); empty object `{}` if no extensions |
| `raw_rule` | The original unmodified rule line from the input, verbatim, including any counter prefix if present |
| `packet_count` | Packet counter value if the input was captured with `--counters`; `null` if not present |
| `byte_count` | Byte counter value if captured with `--counters`; `null` if not present |

**Note on `target_stops_chain_traversal`:** This field records whether the matching packet proceeds to the next rule in the current chain, or whether current-chain traversal stops.

| Target | `target_stops_chain_traversal` | Notes |
|--------|-------------------------------|-------|
| `ACCEPT` | `true` | Packet accepted; chain traversal ends |
| `DROP` | `true` | Packet silently discarded; chain traversal ends |
| `REJECT` | `true` | Packet rejected with a response; chain traversal ends |
| `RETURN` | `true` | Chain traversal ends for the current chain. In a user-defined chain, the packet returns to the calling chain and continues from the rule after the jump — the packet is not terminated. In a built-in chain, the default policy is applied — the packet may then be accepted or dropped. |
| `NFQUEUE` | `true` | Packet diverted to a userspace queue; chain traversal ends. The packet's ultimate fate is determined by the userspace process that reads from the queue. |
| `LOG` | `false` | Packet is logged; traversal continues to the next rule |
| `NFLOG` | `false` | Packet is logged to netlink; traversal continues to the next rule |
| `MARK` | `false` | Packet mark is set; traversal continues to the next rule |
| `CONNMARK` | `false` | Connection mark is set; traversal continues to the next rule |
| `user-defined chain` | `conditional` | Traversal of the current chain is suspended while the user-defined chain is evaluated. If the user-defined chain terminates the packet (ACCEPT, DROP, REJECT), chain traversal ends permanently. If the user-defined chain ends without terminating the packet (falls through or hits RETURN), traversal resumes in the calling chain at the rule after the jump. This cannot be determined from the jump rule alone. |
| `MASQUERADE` / `SNAT` / `DNAT` | `true` | NAT action is recorded in the conntrack table; traversal ends for this chain |

### 5.3 Target parameters and match extension handling

#### Target parameters (`target_params`)

Certain targets carry parameters that are required to interpret the rule's effect. These must be extracted into the `target_params` field:

| Target | Parameters extracted |
|--------|----------------------|
| `REJECT` | `reject_with`: the rejection method (`icmp-port-unreachable`, `tcp-reset`, `icmp-net-unreachable`, `icmp-host-unreachable`, `icmp-proto-unreachable`, `icmp-net-prohibited`, `icmp-host-prohibited`, `icmp-admin-prohibited`). Default is `icmp-port-unreachable` if `--reject-with` is not specified. This matters: `tcp-reset` causes an immediate TCP RST (connection refused); the ICMP variants produce ICMP unreachable messages with different codes; the distinction is visible on the wire and changes the client-side error. |
| `SNAT` | `to_source`: the translated source address or address:port range (e.g., `203.0.113.5`, `203.0.113.5-203.0.113.10`, `203.0.113.5:1024-65535`). Without this value, knowing SNAT is happening is half the answer. |
| `DNAT` | `to_destination`: the translated destination address or address:port (e.g., `10.0.0.5`, `10.0.0.5:8080`). This is the forensic payload of the rule — where is inbound traffic actually being sent? |
| `MASQUERADE` | `to_ports`: optional source port range for masqueraded connections (e.g., `1024-65535`). `null` if not specified (kernel selects a port from the ephemeral range). |
| `NFQUEUE` | `queue_num`: the queue number the packet is sent to (e.g., `0`). Required to identify which userspace process handles the packet. |
| `LOG` | `log_prefix`: the string prepended to the kernel log message. Often identifies which software or policy inserted the rule (e.g., `"fail2ban-sshd "`, `"DOCKER-ISOLATION "`, `"IPT-DENY: "`). `log_level`: the syslog level (`info`, `warn`, `err`, etc.). |
| `MARK` | `set_xmark_value`: the mark value as a hex string (e.g., `"0x1"`). `set_xmark_mask`: the mask as a hex string (e.g., `"0xffffffff"`). Note: `iptables-save` always emits the MARK target as `--set-xmark value/mask` regardless of whether the rule was added with `--set-mark` or `--set-xmark`. The parser will therefore always encounter `--set-xmark` in real inputs. Marks are used by policy routing and by downstream iptables rules that match on `-m mark --mark`. |

#### Match extension modules

iptables rules use extension modules (`-m module_name`) to add match criteria beyond the basic protocol/address/port fields. The following extensions are structured in v1:

| Extension module | Structured fields extracted |
|------------------|----------------------------|
| `conntrack` | `ctstates`: list of connection tracking states matched (e.g., `["ESTABLISHED", "RELATED"]`); `negated`: boolean if `! --ctstate` is used. Supported states: `NEW`, `ESTABLISHED`, `RELATED`, `INVALID`, `UNTRACKED`, `DNAT`, `SNAT`. |
| `state` | `states`: list of states matched (e.g., `["ESTABLISHED", "RELATED"]`); `negated`: boolean. The `state` module is an older syntax backed by the same conntrack kernel subsystem. It supports the common states (`NEW`, `ESTABLISHED`, `RELATED`, `INVALID`) but not the extended states available in the `conntrack` module (`UNTRACKED`, `DNAT`, `SNAT`). Both modules are treated equivalently in the conntrack diagnostic analysis. |
| `multiport` | `destination_ports`: list of ports and port ranges parsed from `--dports` (e.g., `["80", "443", "8080:8090"]`). Ranges are preserved as strings (`"8080:8090"`), not enumerated. When `multiport` is used, `dst_port` in the base record is `null`. `source_ports`: equivalent for `--sports`. `ports`: for the `--ports` flag — matches if the port appears as either the source OR the destination port (OR condition, not AND; a packet need not have the same port on both sides). |
| `tcp` | `flags_mask`: the set of flags to examine — corresponds to the **first** argument of `--tcp-flags`. `flags_match`: the subset of those flags that must be SET — corresponds to the **second** argument. Example: `--tcp-flags SYN,RST,ACK SYN` → `flags_mask: "SYN,RST,ACK"`, `flags_match: "SYN"`. These two field names are easy to swap; getting them reversed produces a structurally valid but semantically wrong record. `option`: TCP option number if `--tcp-option` is used. |
| `udp` | Covered by `src_port` / `dst_port` and their `_negated` booleans in the base record. The `udp` extension adds no fields beyond the base record. |
| `icmp` | `icmp_type`: the ICMP type matched (e.g., `echo-request`, `8/0`, numeric); `negated`: boolean |
| `limit` | `rate`: matched rate (e.g., `5/sec`); `burst`: burst allowance (e.g., `10`) |
| `hashlimit` | `above` or `upto` rate; `burst`; `name`; `mode` (`srcip`, `dstip`, `srcip-dstip`, etc.) |
| `recent` | `name`: list name; `update`/`set`/`check`/`remove`: which operation; `seconds`: time window; `hitcount`: hit threshold; `side`: `source` or `dest` |
| `comment` | `comment_text`: the comment string. Comments are often the most direct indicator of which tool or operator inserted a rule. |
| `iprange` | `src_range`: IP range for `--src-range` (e.g., `10.0.0.1-10.0.0.10`); `dst_range`: for `--dst-range`; `negated`: boolean |
| `addrtype` | `src_type`: address type for source (`LOCAL`, `UNICAST`, `MULTICAST`, etc.); `dst_type`: for destination |
| `mark` (match) | `mark_value`: the mark value matched; `mask`: optional mask; `negated`: boolean |
| `set` | `set_name`: the ipset name referenced; `flags`: match direction (`src`, `dst`) |

For any extension module not in the above list, the rule is parsed as far as possible and the unrecognised extension text is preserved verbatim in the `opaque_extensions` field. The rule is **not** marked as failed; `raw_rule` is always preserved regardless.

**Relationship between base record port fields and multiport extension:** The `dst_port` and `src_port` fields in the base record capture ports specified via `-p tcp/udp --dport/--sport`. When the `multiport` extension (`-m multiport`) is used instead, `dst_port` and `src_port` in the base record are `null`, and the port list is in `match_extensions.multiport.destination_ports` / `source_ports`. These two representations are mutually exclusive for any given rule; a rule cannot use both `--dport` and `--dports` simultaneously.

### 5.4 Diagnostic annotations

Beyond the per-rule record, the module computes and includes a set of diagnostic annotations that directly answer the first questions a network engineer asks during an investigation. These annotations are computed from the parsed rules and do not require any additional input.

**Chain default policy summary:**
- Chains with default policy `DROP` — listed by `table/chain`. A DROP default policy means the chain is deny-by-default: any packet that falls through all rules in the chain without matching is silently discarded. This is the single most important security posture fact about a firewall.
- Chains with default policy `ACCEPT` — listed. These chains rely on explicit DROP or REJECT rules to block specific traffic; unmatched traffic is permitted.
- Note: DROP default policies in tables other than `filter` (e.g., `nat` or `mangle`) are unusual and likely warrant attention.

**Conntrack/state rule position analysis:**
- Location (table, chain, position) of every `conntrack` or `state` module rule that accepts `ESTABLISHED` or `RELATED` traffic in the `filter` table INPUT and FORWARD chains.
- For each such rule: whether any DROP or REJECT rule exists at a lower position number in the same chain. A DROP or REJECT rule that precedes the conntrack acceptance rule is flagged as a potential misplaced-conntrack-rule condition. **This is a warning that requires human verification:** the DROP or REJECT rule may only match specific traffic classes (e.g., `tcp dport 80`) that do not overlap with the return traffic for established sessions; or it may be a broad rule (e.g., `-p tcp -j DROP`) that will intercept established-connection return packets before the conntrack rule is reached. The engineer must examine the preceding rule's match criteria to determine whether an actual fault exists.

**Active rules by counter (when counters are present):**
- All DROP or REJECT rules with `packet_count > 0` — these are actively discarding traffic at the time the capture was made
- Rules with `packet_count = 0` and DROP or REJECT target — present in policy but not yet exercised against any traffic
- The distinction is critical for triage: a DROP rule with zero hits is not the active culprit in a live incident; one with millions of hits is

**NAT summary (when nat table rules are present):**
- All MASQUERADE rules with their source address ranges — indicates this VM is performing source NAT for forwarded traffic; return traffic arrives at this VM's interface address and must be de-NATted by conntrack
- All DNAT rules with `to_destination` values — indicates destination rewriting for inbound traffic; traffic arriving at one address is actually delivered to a different address/port
- All SNAT rules with `to_source` values — static source address rewriting

**User-defined chains:**
- All user-defined chains with the built-in chain rules that jump to them — enabling chain traversal path tracing
- User-defined chains referenced in jump targets but not defined in the input are flagged as unresolved chain references with a parse_warning

---

## 6. What the Module Does NOT Do

The following are explicitly out of scope for this module.

- **IPv6 rules** — `ip6tables-save` output is a separate module (Module 2). IPv4 and IPv6 are independent kernel packet filtering tables; they are never present in the same `iptables-save` output.
- **nftables** — `nft list ruleset` output is a completely different format and data model, handled by a separate module (Module 3). The parser does not attempt to interpret nftables syntax.
- **Live kernel state** — the parser does not execute `iptables-save` itself, connect to a VM, or invoke any command. It parses text that was already captured.
- **Drift comparison** — comparing two parsed rulesets is the responsibility of the diff engine (Module 5). The parser produces the structured data that the diff engine compares.
- **Chain classification** (Docker/kube-proxy/user-defined) — that is Module 6.
- **Packet traversal simulation** — the parser does not simulate whether a specific source/destination/protocol/port combination would be accepted or dropped. It structures the rules; it does not evaluate them against a hypothetical packet. (This capability, sometimes called "policy evaluation" or "shadow analysis", is a separate scope item.)
- **Rule optimisation or redundancy analysis** — whether rules are redundant, unreachable, or suboptimally ordered is not this module's concern.
- **Remediation** — the parser is strictly read-only and produces no output that modifies any firewall state.

---

## 7. Input Specification

### 7.1 Primary input format: `iptables-save` (without counters)

Produced by running `iptables-save` on a Linux VM. Example:

```
# Generated by iptables-save v1.8.7 on Wed Mar 11 14:32:00 2026
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
-A FORWARD -j DOCKER-USER
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -j RETURN
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
COMMIT
```

**Format structure:** An optional leading comment line; then for each table: a table header (`*table_name`), chain policy lines (`:CHAIN_NAME POLICY [policy_packets:policy_bytes]`), zero or more rule lines (`-A CHAIN_NAME ...`), and `COMMIT`. A table with no user-defined rules has only chain policy lines and `COMMIT`.

**User-defined chains** appear in the chain policy section with a `-` where the policy would be: `:DOCKER-USER - [0:0]`. The `-` indicates no default policy. This is the canonical `iptables-save` representation of a user-defined chain with no default policy.

**Negation** appears as `!` immediately before the flag it negates, with a space on either side: `-s ! 192.168.1.0/24` (older syntax) or `! -s 192.168.1.0/24` (modern syntax). Both forms are encountered in real rulesets; the parser must handle both.

### 7.2 Secondary input format: `iptables-save --counters`

Produced by `iptables-save --counters`. Identical to the primary format except that each rule line is prefixed with `[packets:bytes]` in raw integer form:

```
[847291:84729100] -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A INPUT -p icmp -j DROP
```

Counter values in this format are always raw integers — never SI-suffixed. SI suffixes (`K`, `M`, `G`) appear only in the human-readable display output of `iptables -L -v`, which is a different format not supported by this module.

**Format auto-detection:** The parser detects whether counters are present by examining the first rule line encountered. If that line begins with `[`, counters are present for the entire file. If the input contains no rule lines at all (all chains are empty — only chain header lines and `COMMIT` are present), no detection can occur; the parser defaults to `input_format: "iptables-save"` in this case. **If counter prefixes appear inconsistently across rules in the same file (e.g., some lines have `[packets:bytes]` and others do not), the file is malformed. The parser must flag this as a `parse_warning` and continue parsing, treating rules without a counter prefix as having `null` counters.**

### 7.3 Input delivery

The module accepts its input as a string (in-memory text) or as a file path. It does not fetch the input from any network source. Providing the input to the module is the responsibility of the calling layer.

### 7.4 Multi-table input

A single `iptables-save` output contains one or more table blocks (filter, nat, and optionally mangle, raw, security). The parser processes all tables present in the input in a single pass. The caller does not need to split the input by table.

---

## 8. Output Specification

The parser produces a single structured JSON document. The schema below uses `|` to indicate alternatives and `<int>|null` to indicate a nullable integer.

```json
{
  "parsed_at": "<ISO 8601 timestamp>",
  "input_format": "iptables-save" | "iptables-save-counters",
  "tables": {
    "<table_name>": {
      "chains": {
        "<chain_name>": {
          "type": "builtin" | "user-defined",
          "default_policy": "ACCEPT" | "DROP" | null,
          "policy_packet_count": <int> | null,
          "policy_byte_count": <int> | null,
          "rules": [
            {
              "table": "<string>",
              "chain": "<string>",
              "position": <int>,
              "protocol": "<string>" | null,
              "source": "<string>" | null,
              "source_negated": <bool>,
              "destination": "<string>" | null,
              "destination_negated": <bool>,
              "in_interface": "<string>" | null,
              "in_interface_negated": <bool>,
              "out_interface": "<string>" | null,
              "out_interface_negated": <bool>,
              "dst_port": "<string>" | null,
              "dst_port_negated": <bool>,
              "src_port": "<string>" | null,
              "src_port_negated": <bool>,
              "target": "<string>",
              "target_params": { ... } | null,
              "target_stops_chain_traversal": true | false | "conditional",
              "match_extensions": { ... },
              "opaque_extensions": "<string>" | null,
              "raw_rule": "<string>",
              "packet_count": <int> | null,
              "byte_count": <int> | null
            }
          ]
        }
      }
    }
  },
  "diagnostics": {
    "drop_policy_chains": [ "<table>/<chain>", ... ],
    "accept_policy_chains": [ "<table>/<chain>", ... ],
    "conntrack_position_warnings": [
      {
        "table": "<string>",
        "chain": "<string>",
        "conntrack_rule_position": <int>,
        "conntrack_raw_rule": "<string>",
        "preceding_drop_rules": [
          { "position": <int>, "raw_rule": "<string>" }
        ]
      }
    ],
    "active_drop_rules": [ <rule_record>, ... ],
    "nat_summary": {
      "masquerade_rules": [ <rule_record>, ... ],
      "dnat_rules": [ <rule_record>, ... ],
      "snat_rules": [ <rule_record>, ... ]
    },
    "user_defined_chains": {
      "<chain_name>": {
        "referenced_from": [ { "table": "<string>", "chain": "<string>", "position": <int> } ]
      }
    },
    "unresolved_chain_references": [
      { "target_chain": "<string>", "referenced_from": { "table": "<string>", "chain": "<string>", "position": <int> } }
    ]
  },
  "parse_warnings": [ "<string>", ... ]
}
```

**Guarantees:**
- The output is always valid JSON, even for malformed input.
- `parse_warnings` is always an array; it is empty `[]` when there are no warnings.
- `diagnostics` is always present with all keys; sub-arrays are empty `[]` when there is nothing to report.
- `parsed_at` reflects the time of parsing. All other fields in the document — rule records, diagnostics, parse_warnings — are deterministic given the same input (see NFR-04).

---

## 9. Functional Requirements

### Must have

**FR-01** Parse all tables present in a standard `iptables-save` output file: `filter`, `nat`, `mangle`, `raw`, `security`. Tables not present in the input are absent from the output; their absence is not a warning.

**FR-02** Preserve exact rule order within each chain. `position` is assigned by the parser based on the order rule lines appear in the input for each chain, starting at 1. Rule order must never be altered, inferred, or sorted. Chains with no rules are included in the output with an empty `rules` list.

**FR-03** Extract the default policy for every built-in chain. Chain default policy is the verdict applied to any packet that traverses the entire chain without matching any rule. Valid values for chain policy are `ACCEPT` and `DROP` only. `REJECT` is not a valid iptables chain policy — it can only appear as a rule target — and must never appear in the `default_policy` field.

**FR-04** Correctly identify which targets stop traversal of the current chain. `ACCEPT`, `DROP`, `REJECT`, `RETURN`, `NFQUEUE`, `MASQUERADE`, `SNAT`, and `DNAT` all stop traversal of the current chain (`target_stops_chain_traversal: true`). `LOG`, `NFLOG`, `MARK`, and `CONNMARK` do not stop traversal — the packet continues to the next rule (`target_stops_chain_traversal: false`). A jump to a user-defined chain produces `target_stops_chain_traversal: "conditional"` — traversal of the current chain is suspended, and whether it is ultimately terminated depends on what happens inside the called chain. Note on NFQUEUE specifically: NFQUEUE diverts the packet to a userspace queue and stops kernel chain traversal; it is terminating for chain traversal purposes even though the packet's ultimate fate is determined by the userspace process.

**FR-05** Correctly record `RETURN` target semantics in the `target_params` context field. `RETURN` stops traversal of the current chain. Its effect on the packet depends on where it appears: in a user-defined chain, the packet returns to the calling chain and continues from the rule after the jump (packet is not terminated); in a built-in chain, the chain's default policy is applied. The `raw_rule` is always preserved; documenting this distinction supports correct downstream reasoning.

**FR-06** Handle negation (`!`) in all match criteria fields. Negated fields must be recorded with their corresponding `_negated: true` boolean. The actual value field (e.g., `source`) records the address or interface value; the `_negated` boolean records that the match is inverted. A rule with `! -s 192.168.1.0/24` matches traffic from any source *except* 192.168.1.0/24 — this is semantically inverted from the non-negated case and must not be conflated with it.

**FR-07** Parse and record target parameters for targets that have them: `REJECT --reject-with`, `SNAT --to-source`, `DNAT --to-destination`, `MASQUERADE --to-ports`, `NFQUEUE --queue-num`, `LOG --log-prefix` and `--log-level`, `MARK --set-mark`. A REJECT rule without an explicit `--reject-with` value defaults to `icmp-port-unreachable` and must be recorded as such.

**FR-08** Parse counter values from `iptables-save --counters` format. Counters in this format are raw integers. Counter values are stored in `packet_count` and `byte_count` as integers. Absence of counters is represented as `null`, not as zero — `null` means "not captured"; `0` means "captured and zero packets matched this rule."

**FR-09** Detect and record conntrack/state rule position warnings. When a `conntrack` or `state` match rule accepting `ESTABLISHED` or `RELATED` traffic exists in the filter table INPUT or FORWARD chain, and any DROP or REJECT rule exists at a lower position number in the same chain, record a warning in `diagnostics.conntrack_position_warnings`. The warning records the conntrack rule's position and the preceding DROP/REJECT rules. It does not conclude that a fault exists — that determination requires examining the preceding rule's match criteria, which is the engineer's task.

**FR-10** Handle user-defined chains correctly. User-defined chains have `default_policy: null`. A packet that reaches the end of a user-defined chain without matching any rule returns to the calling chain. User-defined chains referenced by jump targets but not defined in the input are flagged in `diagnostics.unresolved_chain_references` and in `parse_warnings`.

**FR-11** Detect truncated or malformed input. A valid `iptables-save` table block always ends with `COMMIT`. If the input ends without a final `COMMIT`, or if a `COMMIT` is missing for a started table block, the parser must add an entry to `parse_warnings` that the input appeared incomplete. Partial output for the incomplete table block is still included in the output under the partially parsed table.

**FR-12** Accept input as both an in-memory string and a file path pointing to an `iptables-save` output file.

**FR-13** Never fail completely on unrecognised extension modules. Any rule line containing an unrecognised extension module must be parsed as completely as possible, with the unrecognised extension text stored in `opaque_extensions`. The `raw_rule` must be preserved verbatim. The parser must continue processing all remaining rules. An entry is added to `parse_warnings` for the unrecognised extension.

### Good to have

**FR-14** Produce a chain traversal map in `diagnostics.user_defined_chains` that records, for each user-defined chain, which built-in chain rules reference it — enabling an engineer to trace the full evaluation path for a given packet type without manually following jump targets across the rule set.

**FR-15** For the nat table diagnostics, record the `to_destination` value from DNAT rules and `to_source` from SNAT rules prominently in `diagnostics.nat_summary`, not only in the per-rule record — so the NAT translation map is immediately visible without iterating through all rules.

**FR-16** Identify rules in the filter table that perform logging (`LOG` or `NFLOG` target) and surface their `log_prefix` values in the diagnostics summary — log prefixes often identify which software (fail2ban, Docker, kube-proxy) inserted surrounding rules and are high-value forensic signals.

### Out of scope for v1

**FR-17** Packet traversal simulation — evaluating whether a specific packet would be accepted or dropped.

**FR-18** Policy evaluation against an external access policy specification.

**FR-19** Rule optimisation or redundancy analysis.

**FR-20** `iptables -L -v` display format parsing — this is a different, substantially more complex format with SI-suffixed counters and variable column widths. Explicitly excluded; `iptables-save` format only.

---

## 10. Non-Functional Requirements

**NFR-01 Correctness above all else.** A wrong parse — one that misrepresents a DROP as ACCEPT, inverts a negated match, misreports a chain default policy, or drops a rule from the output — is more damaging than returning a parse warning. When the parser cannot structure a rule unambiguously, it must preserve the raw rule and emit a warning rather than guess.

**NFR-02 No false positives from counter variation.** Two `iptables-save --counters` captures of an identical ruleset taken at different times, with different counter values, must produce rule records that are identical when `packet_count` and `byte_count` are excluded. Counters must not affect any other field in the rule record.

**NFR-03 Raw rule always preserved.** Every rule line from the input must appear verbatim in the `raw_rule` field of its corresponding rule record, regardless of how successfully the rule was parsed. There is no condition under which a rule line is silently absent from the output.

**NFR-04 Deterministic rule records.** Parsing the same input twice must produce identical `tables`, `diagnostics`, `parse_warnings`, and all rule record fields. The `parsed_at` timestamp field is excluded from this guarantee — it records when parsing occurred and will differ between invocations. All other output fields must be deterministic given identical input.

**NFR-05 No silent truncation.** If the input is truncated mid-table-block (missing `COMMIT`), the parser must flag this in `parse_warnings`. Partial results for the truncated table are included but the warning must be present and unambiguous. The parser must not silently produce output that looks complete when the input was not.

**NFR-06 Handles large rulesets without degradation.** A Kubernetes node with 2,000 iptables rules across all tables must be parsed to the same correctness standard as a bare VM with ten rules. There is no rule count at which the parser approximates, summarises, or truncates.

---

## 11. Competitive Landscape

The following tools exist in adjacent space. None fully addresses the use case this module targets.

---

### `iptables-xml`

**What it is:** A utility included in the iptables package on most Linux distributions. Reads `iptables-save` output from stdin and produces XML. Invoked as `iptables-save | iptables-xml`.

**What it does:** Format conversion from `iptables-save` text to XML. Each rule becomes an XML element with attributes corresponding to the parsed flags.

**What it does not do:**
- Produces XML only — no JSON and no queryable structured format suited to modern investigation workflows
- No diagnostic annotations: no chain default policy summary, no conntrack position analysis, no active-DROP-rule identification, no NAT summary
- No negation representation — the `!` qualifier is not reflected in the XML output in a queryable way
- No counter parsing or counter/rule separation for the `--counters` format
- Extension modules beyond basic flags are encoded as raw attribute text, not structured fields
- Not maintained as a standalone project — ships with iptables and is only updated when iptables is updated

**Assessment:** `iptables-xml` solves the same input parsing problem but produces output in a format designed for 2005-era XML tooling, with none of the diagnostic annotations this module provides. An engineer using `iptables-xml` still needs to query and interpret the XML output manually.

---

### `python-iptables`

**What it is:** An open-source Python library available on PyPI that provides Python bindings to the Linux kernel's netfilter subsystem via the `libiptc` library.

**What it does:** Reads the **live, running kernel state** directly. Allows Python code to enumerate tables, chains, and rules from the currently-running kernel without invoking the `iptables` binary.

**What it does not do:**
- Cannot parse `iptables-save` files — it interfaces with the live kernel, not saved artifacts. This is a fundamental architectural difference that makes it inapplicable to offline forensic analysis.
- Requires the Python process to run as root or with `CAP_NET_ADMIN` on the machine whose firewall is being inspected — impossible in a cloud forensics context where analysis runs on a workstation
- Cannot be used to analyse historical captures, incident artifacts, or output from a remote VM
- Depends on `libiptc`, which is deprecated and absent on systems using the iptables-nft backend (RHEL 8+, Ubuntu 20.04+) — rendering the library non-functional on the majority of modern Linux distributions
- Has not had an active release since 2018

**Assessment:** `python-iptables` solves a different problem — live programmatic firewall management from Python on the same machine. It cannot substitute for this module in any of the target use cases.

---

### `iptables-optimizer`

**What it is:** An open-source command-line tool (Perl) that reads `iptables-save` format and analyses the ruleset for optimisation opportunities.

**What it does:** Identifies redundant rules (completely shadowed by a prior rule), unreachable rules, and suggests rule reordering to reduce average packet evaluation time. Outputs a modified `iptables-save` file.

**What it does not do:**
- Produces a modified `iptables-save` file as output, not a structured data format for downstream analysis
- No diagnostic annotations for security or forensics use
- Does not parse or preserve counter values from `iptables-save --counters` format
- Focused on performance engineering, not incident investigation or compliance auditing
- Not actively maintained

**Assessment:** `iptables-optimizer` solves a performance engineering problem using the same input format. It produces fundamentally different output for a completely different use case. No overlap with the forensic and diagnostic value this module delivers.

---

### Enterprise Firewall Management Platforms (Tufin, AlgoSec, FireMon)

**What they are:** Enterprise-grade multi-vendor firewall policy management platforms. They ingest rule bases from Cisco ASA, Palo Alto, Check Point, iptables, and other vendors into a unified management environment.

**What they do:** Provide unified policy views across a multi-vendor fleet, generate compliance reports against security frameworks, track policy changes over time, visualise access paths between network zones, and support change management workflows including rule request approvals.

**What they do not do:**
- Not accessible to an individual engineer for a point investigation — they are deployed as enterprise platforms with dedicated firewall operations teams and significant ongoing administration overhead
- Require enterprise procurement, licensing (typically tens to hundreds of thousands of dollars annually), and multi-week deployment projects before they deliver value
- Not designed for real-time incident investigation against a freshly captured `iptables-save` file — they are governance platforms, not forensics tools
- Do not produce the per-session, per-investigation structured artifact an engineer needs to attach to an incident ticket or include in a post-incident review
- Not cloud-native: they do not integrate with Azure VM run-command, Azure audit trails, or the broader cloud investigation workflow

**Assessment:** These platforms address fleet-wide firewall governance at enterprise scale. They are not alternatives for a cloud network engineer running a point investigation on a single VM during an active incident.

---

### Manual `grep` and shell pipelines

The de facto standard for querying an `iptables-save` file today: `grep -n "dport 8443" /etc/iptables/rules.v4`, or `awk '/\*filter/,/COMMIT/' rules.v4 | grep DROP`.

**What this approach does not do:**
- Does not account for chain default policy — a grep that finds a matching ACCEPT rule does not reveal whether a DROP rule at a lower position number fires first
- Does not handle negated match criteria — `! -s 10.0.0.0/8` matches everything *except* that prefix; grep for a source IP misses negated rules entirely
- Does not follow user-defined chain jumps and RETURN targets to determine the actual traversal path
- Produces no structured output and no persistent artifact
- Requires the engineer to know iptables syntax well enough to interpret every rule correctly, including extension module flags

**Assessment:** The most common current alternative and the baseline against which every improvement this module delivers should be measured. Every use case described in Section 3 is one the engineer is currently solving with grep, incorrectly or at significant time cost.

---

## 12. Prerequisites for Building This Module

The following must be in place before development begins. These are product and operational prerequisites — not implementation choices.

### P-1: Real iptables-save fixture library (blocking prerequisite)

The single most important prerequisite, documented in `vm-firewall-inspector-build-challenges.md`. A parser built and tested only against synthetic inputs will be incomplete in ways that do not surface until the first real production VM is tested. The fixture library must be collected from real Linux VMs before any parsing logic is written.

Required fixtures — collected with both `iptables-save` (no counters) and `iptables-save --counters`:

| VM configuration | Why required |
|------------------|--------------|
| Clean Ubuntu 22.04 with no modifications | Baseline: minimal ruleset, iptables-nft backend, verifies basic parse path |
| RHEL 8 with CIS Level 1 hardening applied | CIS hardening scripts add rules using `recent`, `hashlimit`, and `limit` extensions; iptables-nft backend; common in enterprise Azure fleets |
| Ubuntu 22.04 with Docker installed and running containers | Docker injects `DOCKER`, `DOCKER-USER`, `DOCKER-ISOLATION-STAGE-1/2` chains and MASQUERADE rules in the nat table; validates negation parsing (`! -o docker0`), user-defined chain handling, and large rulesets |
| Kubernetes node (any distribution) with kube-proxy running and active services | kube-proxy injects hundreds of rules across `KUBE-SERVICES`, `KUBE-SEP-*`, and `KUBE-FORWARD` chains; DNAT rules in nat PREROUTING; validates large ruleset handling and DNAT target parameter parsing |
| VM with fail2ban active (at minimum: sshd jail) | fail2ban creates `f2b-*` user-defined chains with DROP rules for banned source IPs; validates dynamic chain and counter handling |
| VM with WireGuard installed and a tunnel configured | WireGuard adds rules to the filter table FORWARD and INPUT chains for tunnel traffic; validates interface-based match criteria |

A minimum of six fixture files is required before development begins. Each should represent a different rule composition and extension module set so the parser is tested against genuinely diverse inputs from the start.

### P-2: Agreed output schema (blocking prerequisite)

The JSON output schema — field names, types, nesting structure, negation representation, and null-versus-absent semantics — must be agreed and documented before the first line of parsing logic is written. This schema is the contract between this module and every downstream consumer (the diff engine, Ghost Agent, compliance reporting). A schema change after downstream consumers are built breaks the integration.

### P-3: Scope decision — which extension modules are structured in v1

The list of extension modules that will be fully structured (producing explicit field values) versus stored as opaque text must be agreed before development. The recommended v1 set: `conntrack`, `state`, `multiport`, `tcp` flags, `icmp` type, `limit`, `hashlimit`, `recent`, `comment`, `iprange`, `addrtype`, `mark` (match), `set`. All others: opaque. Adding a new extension to the structured set mid-build requires retesting all fixtures.

### P-4: Decision — `iptables -L -v` display format in or out of scope

Confirm explicitly whether the `iptables -L -v` display format (SI-suffixed packet counts, variable column widths) is in scope. The recommendation is that it is **not** in scope for v1 — `iptables-save` and `iptables-save --counters` only. The display format requires a substantially more complex parser and is not needed for any of the forensic use cases described in this document. This must be an explicit decision, not an assumption.

### P-5: Acceptance criteria definition

Define what "correct" parsing means before writing the first test. The recommended criterion: given an `iptables-save` input, the parser must produce rule records such that serialising them back to `iptables-save` format produces output that `iptables-restore` would accept and that would produce a functionally equivalent ruleset. This round-trip property is the most direct and complete correctness test. Define explicitly which fields are included in the equivalence check (counters excluded; rule order and all match criteria included).

### P-6: Test VM access for fixture collection

Linux VMs running the required distributions, with root privileges to install Docker, Kubernetes, fail2ban, and WireGuard, and to run `iptables-save --counters`. These are needed only for the one-time fixture collection exercise — the parser module itself requires no VM access for development or testing once the fixtures are collected.
