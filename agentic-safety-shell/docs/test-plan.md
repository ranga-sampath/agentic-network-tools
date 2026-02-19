# Test Plan: Safe-Exec Shell

> Golden test suite derived from `architecture.md` and `design.md`. Every test case traces to a specific specification clause. This plan is the acceptance gate — feature code ships only when the required tiers pass.

---

## Priority Tiers

| Tier | Label | Meaning | Ship Blocker? |
|------|-------|---------|---------------|
| P0 | **MUST PASS** | Safety-critical invariants. A single failure means the shell is unsafe to deploy. These tests protect against catastrophic outcomes: data destruction, secret leakage, safety bypass. | Yes — 100% pass rate required |
| P1 | **SHOULD PASS** | Behavioral correctness for the core pipeline. Failures indicate real bugs that affect classification accuracy, HITL behavior, or response contract compliance. Not immediately dangerous but functionally broken. | Yes — all must pass before merge |
| P2 | **GOOD TO PASS** | Quality, completeness, and usability. Covers metadata accuracy, truncation formatting, audit schema completeness, and anonymization. Failures are acceptable during early iterations but must be resolved before production. | No — tracked as known gaps |
| P3 | **MAY FAIL** | Environmental dependencies, timing-sensitive behavior, and OS-specific edge cases. These test real subprocess execution, filesystem I/O, and timeout enforcement. Intermittent failures are expected in CI; consistent failures require investigation. | No — informational |

---

## Notation

- **`->`** means "expected classification or outcome"
- Each test has an ID: `{Section}.{Number}` (e.g., `T0.01`)
- `[spec: ...]` traces the test to a specific document clause
- All tests use the `execute({ command, reasoning })` interface unless stated otherwise
- HITL tests use a mock/stub for the approval prompt; they do not require a real terminal

---

## Section 1 — Tier 0: Forbidden Commands

### P0 — MUST PASS

These tests verify that catastrophic commands are blocked unconditionally with no path to execution.

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T0.01 | `rm -rf /` | -> FORBIDDEN, `status: "error"`, `error: "forbidden_command"` | [spec: design.md Tier 0 table, row 1] |
| T0.02 | `rm -rf /*` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 1 — `rm -rf /*` variant] |
| T0.03 | `mkfs.ext4 /dev/sda1` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 2] |
| T0.04 | `mkfs /dev/sda` | -> FORBIDDEN | `mkfs` without filesystem type — still a format command |
| T0.05 | `dd if=/dev/zero of=/dev/sda` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 3] |
| T0.06 | `dd if=/dev/urandom of=/dev/sda1` | -> FORBIDDEN | Variant: different input source, still writes to block device |
| T0.07 | `:(){ :\|:& };:` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 4 — fork bomb] |
| T0.08 | `shutdown now` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 5] |
| T0.09 | `shutdown -h now` | -> FORBIDDEN | Variant with flag |
| T0.10 | `reboot` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 5] |
| T0.11 | `halt` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 5] |
| T0.12 | `poweroff` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 5] |
| T0.13 | `init 0` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 6] |
| T0.14 | `init 6` | -> FORBIDDEN | [spec: design.md Tier 0 table, row 6] |

**Behavioral invariants (T0.15–T0.19):**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| T0.15 | FORBIDDEN response has `exit_code: null` — command was never executed | [spec: design.md response contract — null if not executed] |
| T0.16 | FORBIDDEN response has `output: ""` — no output generated | [spec: design.md response contract — empty if errored before execution] |
| T0.17 | FORBIDDEN response has `duration_seconds: null` | [spec: design.md response contract — null if not executed] |
| T0.18 | HITL prompt is **never** invoked for a FORBIDDEN command (mock HITL callback must have zero calls) | [spec: architecture.md Stage 1 — FORBIDDEN short-circuits before Stage 2] |
| T0.19 | FORBIDDEN command produces an audit log entry (unlike empty commands, which do not) | [spec: design.md audit trail — "Forbidden commands ARE logged"] |

**Negative — must NOT be FORBIDDEN (T0.20–T0.23):**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T0.20 | `rm /tmp/results.txt` | -> RISKY (Tier 3), **not** FORBIDDEN | [spec: design.md — "A user might legitimately `rm` a temp file (RISKY, approvable)"] |
| T0.21 | `rm -rf /tmp/test` | -> RISKY (Tier 3), **not** FORBIDDEN | Only `rm -rf /` and `rm -rf /*` are forbidden; path-specific rm is Tier 3 RISKY |
| T0.22 | `dd if=input.pcap of=output.pcap` | -> RISKY (Tier 3), **not** FORBIDDEN | `dd` to regular files is not forbidden; only `dd` to block devices |
| T0.23 | `init 3` | -> RISKY or SAFE depending on classification, **not** FORBIDDEN | Only `init 0` and `init 6` are specified as forbidden |

---

## Section 2 — Tier 1: Command Allowlist

### P0 — MUST PASS

The default-deny invariant: any command not in the allowlist must be classified RISKY.

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T1.01 | `systemctl status nginx` | -> RISKY (Tier 1) | [spec: architecture.md Tier 1 example — `systemctl` not in allowlist] |
| T1.02 | `apt-get install curl` | -> RISKY (Tier 1) | Package manager — not in allowlist |
| T1.03 | `python3 -c "print('hello')"` | -> RISKY (Tier 1) | Arbitrary code execution — not in allowlist |
| T1.04 | `cat /etc/passwd` | -> RISKY (Tier 1) | `cat` not in allowlist |
| T1.05 | `wget http://example.com/file` | -> RISKY (Tier 1) | `wget` not in allowlist |
| T1.06 | `totally_made_up_command --foo` | -> RISKY (Tier 1) | Unknown commands default to RISKY |

### P1 — SHOULD PASS

Every allowlisted command with safe arguments must classify SAFE.

**Network Discovery commands:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T1.10 | `ping 8.8.8.8` | -> SAFE | [spec: design.md Tier 1 — ping, all flags] |
| T1.11 | `ping -c 4 10.0.0.1` | -> SAFE | ping with count flag |
| T1.12 | `traceroute 8.8.8.8` | -> SAFE | [spec: design.md Tier 1] |
| T1.13 | `dig google.com` | -> SAFE | [spec: design.md Tier 1] |
| T1.14 | `dig @8.8.8.8 google.com MX` | -> SAFE | dig with server and record type |
| T1.15 | `nslookup google.com` | -> SAFE | [spec: design.md Tier 1] |
| T1.16 | `host google.com` | -> SAFE | [spec: design.md Tier 1] |
| T1.17 | `whois google.com` | -> SAFE | [spec: design.md Tier 1] |
| T1.18 | `mtr --report 8.8.8.8` | -> SAFE | [spec: design.md Tier 1] |

**System State commands:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T1.20 | `netstat -an` | -> SAFE | [spec: design.md Tier 1 — all flags] |
| T1.21 | `ss -tulnp` | -> SAFE | [spec: design.md Tier 1 — all flags] |
| T1.22 | `lsof -i` | -> SAFE | [spec: design.md Tier 1] |
| T1.23 | `scutil --dns` | -> SAFE | [spec: design.md Tier 1] |
| T1.24 | `scutil --proxy` | -> SAFE | [spec: design.md Tier 1] |
| T1.25 | `scutil --nwi` | -> SAFE | [spec: design.md Tier 1] |

**Flag-sensitive commands — SAFE cases:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T1.30 | `ifconfig` | -> SAFE | [spec: design.md — no arguments = display only] |
| T1.31 | `ifconfig en0` | -> SAFE | [spec: design.md — interface name only] |
| T1.32 | `ip addr show` | -> SAFE | [spec: design.md — `show` subcommand] |
| T1.33 | `ip route show` | -> SAFE | [spec: design.md] |
| T1.34 | `ip link show` | -> SAFE | [spec: design.md] |
| T1.35 | `ip neigh show` | -> SAFE | [spec: design.md] |
| T1.36 | `arp -a` | -> SAFE | [spec: design.md] |
| T1.37 | `arp -n` | -> SAFE | [spec: design.md] |
| T1.38 | `route get 8.8.8.8` | -> SAFE | [spec: design.md — `get` subcommand] |
| T1.39 | `networksetup -listallnetworkservices` | -> SAFE | [spec: design.md — `-list*`] |
| T1.40 | `networksetup -getinfo Wi-Fi` | -> SAFE | [spec: design.md — `-get*`] |

**Flag-sensitive commands — RISKY cases:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T1.50 | `ifconfig en0 up` | -> RISKY | [spec: design.md — `up` flag] |
| T1.51 | `ifconfig en0 down` | -> RISKY | [spec: design.md — `down` flag] |
| T1.52 | `ifconfig en0 mtu 9000` | -> RISKY | [spec: design.md — `mtu` flag] |
| T1.53 | `ifconfig en0 192.168.1.100` | -> RISKY | [spec: design.md — address assignment] |
| T1.54 | `ip addr add 10.0.0.5/24 dev eth0` | -> RISKY | [spec: design.md — `add` subcommand] |
| T1.55 | `ip route del default` | -> RISKY | [spec: design.md — `del` subcommand] |
| T1.56 | `ip link set eth0 down` | -> RISKY | [spec: design.md — `set` subcommand] |
| T1.57 | `ip neigh flush all` | -> RISKY | [spec: design.md — `flush` subcommand] |
| T1.58 | `arp -d 10.0.0.1` | -> RISKY | [spec: design.md — `-d` (delete)] |
| T1.59 | `arp -s 10.0.0.1 aa:bb:cc:dd:ee:ff` | -> RISKY | [spec: design.md — `-s` (set)] |
| T1.60 | `route add default gw 10.0.0.1` | -> RISKY | [spec: design.md — `add`] |
| T1.61 | `route delete default` | -> RISKY | [spec: design.md — `delete`] |
| T1.62 | `route flush` | -> RISKY | [spec: design.md — `flush`] |
| T1.63 | `networksetup -setairportpower en0 on` | -> RISKY | [spec: design.md — `-set*`] |
| T1.64 | `networksetup -addpreferredwirelessnetwork en0 TestNet` | -> RISKY | [spec: design.md — `-add*`] |
| T1.65 | `networksetup -removenetworkservice TestVPN` | -> RISKY | [spec: design.md — `-remove*`] |

**Data Analysis commands:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T1.70 | `tshark -r capture.pcap` | -> SAFE | [spec: design.md — `-r` present] |
| T1.71 | `tshark -r capture.pcap -Y "tcp.port == 443"` | -> SAFE | `-r` present with display filter |
| T1.72 | `tshark -i eth0` | -> RISKY | [spec: design.md — no `-r`, live capture] |
| T1.73 | `tshark` | -> RISKY | [spec: design.md — no `-r`] |
| T1.74 | `tcpdump -r capture.pcap` | -> SAFE | [spec: design.md — `-r` present] |
| T1.75 | `tcpdump -i en0` | -> RISKY | [spec: design.md — no `-r`, live capture] |
| T1.76 | `pcap_forensics.py --input capture.pcap --output report.json` | -> SAFE | [spec: design.md — always safe] |
| T1.77 | `curl http://example.com` | -> SAFE | [spec: design.md — GET default] |
| T1.78 | `curl -X GET http://example.com/api` | -> SAFE | [spec: design.md — explicit GET] |
| T1.79 | `curl -X POST http://example.com/api` | -> RISKY | [spec: design.md — POST] |
| T1.80 | `curl -X PUT http://example.com/api` | -> RISKY | [spec: design.md — PUT] |
| T1.81 | `curl -X DELETE http://example.com/api` | -> RISKY | [spec: design.md — DELETE] |
| T1.82 | `curl -X PATCH http://example.com/api` | -> RISKY | [spec: design.md — PATCH] |
| T1.83 | `curl -d '{"key":"val"}' http://example.com/api` | -> RISKY | [spec: design.md — `-d`] |
| T1.84 | `curl --data '{"key":"val"}' http://example.com/api` | -> RISKY | [spec: design.md — `--data`] |
| T1.85 | `curl --upload-file report.json http://example.com/upload` | -> RISKY | [spec: design.md — `--upload-file`] |

---

## Section 3 — Tier 2: Azure CLI Verb Rules

### P1 — SHOULD PASS

**Safe verbs (read-only):**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T2.01 | `az vm list` | -> SAFE | [spec: design.md — `list` verb] |
| T2.02 | `az network nsg show --name web-nsg --resource-group prod-rg` | -> SAFE | [spec: design.md — `show` verb] |
| T2.03 | `az keyvault secret get --name dbpass --vault-name myvault` | -> SAFE | [spec: design.md — `get` verb] |
| T2.04 | `az network dns record-set check --name test --zone-name example.com` | -> SAFE | [spec: design.md — `check` verb] |
| T2.05 | `az group exists --name prod-rg` | -> SAFE | [spec: design.md — `exists` verb] |
| T2.06 | `az vm wait --created --name web-01 --resource-group prod-rg` | -> SAFE | [spec: design.md — `wait` verb] |
| T2.07 | `az network watcher show-topology --resource-group prod-rg` | -> SAFE | [spec: design.md special cases] |
| T2.08 | `az network watcher show-next-hop --vm web-01 --resource-group prod-rg --dest-ip 10.0.0.5` | -> SAFE | [spec: design.md special cases] |
| T2.09 | `az network watcher flow-log list --nsg web-nsg --resource-group prod-rg` | -> SAFE | [spec: design.md special cases — read verb] |
| T2.10 | `az login` | -> SAFE | [spec: design.md special cases — not mutative] |
| T2.11 | `az account show` | -> SAFE | [spec: design.md special cases] |

**Risky verbs (mutative):**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T2.20 | `az vm create --name test-vm --resource-group dev-rg --image UbuntuLTS` | -> RISKY (Tier 2) | [spec: design.md — `create` verb] |
| T2.21 | `az group delete --name dev-rg --yes` | -> RISKY (Tier 2) | [spec: design.md — `delete` verb] |
| T2.22 | `az vm update --name web-01 --resource-group prod-rg --set tags.env=staging` | -> RISKY (Tier 2) | [spec: design.md — `update` verb] |
| T2.23 | `az network nsg rule set --name allow-ssh --nsg-name web-nsg --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md — `set` verb] |
| T2.24 | `az network vnet subnet add --name backend --vnet-name main-vnet --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md — `add` verb] |
| T2.25 | `az network nsg rule remove --name allow-ssh --nsg-name web-nsg --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md — `remove` verb] |
| T2.26 | `az vm start --name web-01 --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md — `start` verb] |
| T2.27 | `az vm stop --resource-group prod --name web-01` | -> RISKY (Tier 2) | [spec: design.md — `stop` verb] |
| T2.28 | `az vm restart --name web-01 --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md — `restart` verb] |
| T2.29 | `az vm deallocate --name web-01 --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md — `deallocate` verb] |
| T2.30 | `az resource move --ids /subscriptions/abc/resourceGroups/src --destination-group dest` | -> RISKY (Tier 2) | [spec: design.md — `move` verb] |
| T2.31 | `az network dns zone import --name example.com --resource-group dns-rg --file-name zone.txt` | -> RISKY (Tier 2) | [spec: design.md — `import` verb] |
| T2.32 | `az network dns zone export --name example.com --resource-group dns-rg` | -> RISKY (Tier 2) | [spec: design.md — `export` verb] |
| T2.33 | `az rest --method POST --url https://management.azure.com/...` | -> RISKY (Tier 2) | [spec: design.md special cases — `az rest` always RISKY] |
| T2.34 | `az rest --method GET --url https://management.azure.com/...` | -> RISKY (Tier 2) | `az rest` is always RISKY regardless of HTTP method |
| T2.35 | `az network watcher packet-capture create --vm web-01 --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md special cases — creates resource] |
| T2.36 | `az network watcher flow-log create --nsg web-nsg --resource-group prod-rg` | -> RISKY (Tier 2) | [spec: design.md special cases — mutative verb] |

---

## Section 4 — Tier 3: Dangerous Pattern Detection

### P0 — MUST PASS

Tier 3 patterns must override SAFE classifications from Tiers 1–2. These tests verify that wrapping a safe command in a dangerous pattern forces RISKY.

**Privilege escalation:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T3.01 | `sudo ping 8.8.8.8` | -> RISKY (Tier 3) | [spec: design.md — `sudo` overrides safe `ping`] |
| T3.02 | `sudo az vm list` | -> RISKY (Tier 3) | `sudo` overrides safe Azure read |
| T3.03 | `su -c "netstat -an"` | -> RISKY (Tier 3) | [spec: design.md — `su`] |
| T3.04 | `doas traceroute 10.0.0.1` | -> RISKY (Tier 3) | [spec: design.md — `doas`] |

**Shell evasion:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T3.10 | `bash -c "ping 8.8.8.8"` | -> RISKY (Tier 3) | [spec: design.md — `bash -c`] |
| T3.11 | `sh -c "dig google.com"` | -> RISKY (Tier 3) | [spec: design.md — `sh -c`] |
| T3.12 | `eval "ping 8.8.8.8"` | -> RISKY (Tier 3) | [spec: design.md — `eval`] |
| T3.13 | `exec ping 8.8.8.8` | -> RISKY (Tier 3) | [spec: design.md — `exec`] |
| T3.14 | `` ping `hostname` `` | -> RISKY (Tier 3) | [spec: design.md — backtick substitution] |
| T3.15 | `ping $(hostname)` | -> RISKY (Tier 3) | [spec: design.md — `$()` substitution] |

**Destructive operators:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T3.20 | `netstat > /etc/resolv.conf` | -> RISKY (Tier 3) | [spec: design.md — redirect to system path] |
| T3.21 | `dig google.com >> /etc/hosts` | -> RISKY (Tier 3) | Append redirect to system path |
| T3.22 | `rm -rf /tmp/results` | -> RISKY (Tier 3) | [spec: design.md — `rm`] |
| T3.23 | `chmod 777 /etc/hosts` | -> RISKY (Tier 3) | [spec: design.md — `chmod`] |
| T3.24 | `chown root:root /tmp/file` | -> RISKY (Tier 3) | [spec: design.md — `chown`] |
| T3.25 | `kill -9 1234` | -> RISKY (Tier 3) | [spec: design.md — `kill`] |
| T3.26 | `killall nginx` | -> RISKY (Tier 3) | [spec: design.md — `killall`] |
| T3.27 | `pkill -f "python"` | -> RISKY (Tier 3) | [spec: design.md — `pkill`] |
| T3.28 | `mv /etc/hosts /etc/hosts.bak` | -> RISKY (Tier 3) | [spec: design.md — `mv` to system path] |

**Command chaining:**

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| T3.30 | `ping 8.8.8.8 && rm -rf /tmp` | -> RISKY (Tier 3) | [spec: design.md — `&&` chain, highest risk wins] |
| T3.31 | `ping 8.8.8.8 \|\| reboot` | -> RISKY (Tier 3) | [spec: design.md — `\|\|` chain] |
| T3.32 | `dig google.com ; shutdown now` | -> RISKY (at minimum; `shutdown` may also trigger FORBIDDEN depending on implementation — see T3.32a) | [spec: design.md — `;` chain] |
| T3.32a | `dig google.com ; shutdown now` | Verify: does the forbidden `shutdown` in a chain trigger FORBIDDEN for the entire chain, or does chaining analysis happen at Tier 3 (RISKY)? Implementation must decide; test documents the boundary. | [spec: ambiguity — Tier 0 checks happen before Tier 3 chaining analysis] |
| T3.33 | `netstat -an \| tee /etc/hosts` | -> RISKY (Tier 3) | [spec: design.md — pipe with destructive right side] |
| T3.34 | `netstat -an \| grep 443` | -> RISKY (Tier 3) | [spec: design.md edge cases — `grep` not in allowlist, chain rule applies] |
| T3.35 | `ping 8.8.8.8 && dig google.com` | -> RISKY (Tier 3) | Even though both commands are individually SAFE, chaining with `&&` is a dangerous pattern |

---

## Section 5 — HITL Gate

### P0 — MUST PASS

Fail-closed invariants. The HITL mechanism must never silently approve a RISKY command.

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| H.01 | RISKY command + user denies | `status: "denied"`, `action: "user_denied"`, no execution | [spec: design.md HITL — Deny option] |
| H.02 | RISKY command + HITL timeout expires | `status: "denied"`, `action: "user_abandoned"` | [spec: design.md — silence is not consent] |
| H.03 | RISKY command + simulated terminal close | `status: "denied"`, `action: "user_abandoned"` | [spec: design.md — broken session is not approval] |
| H.04 | RISKY command + HITL mechanism throws exception | `status: "denied"` | [spec: design.md — "if we can't ask, we can't execute"] |
| H.05 | SAFE command | HITL gate is **not** invoked; command proceeds directly to execution | [spec: architecture.md Stage 2 — SAFE commands pass through] |
| H.06 | FORBIDDEN command | HITL gate is **not** invoked; error returned before Stage 2 | [spec: architecture.md — FORBIDDEN short-circuits] |

### P1 — SHOULD PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| H.10 | RISKY command + user approves | `status: "completed"`, `action: "user_approved"`, command is executed | [spec: design.md HITL — Approve option] |
| H.11 | RISKY command + user modifies to SAFE command | Modified command is re-classified from Tier 1; if SAFE, executed without further prompting; `action: "user_modified"` | [spec: design.md HITL — Modify option] |
| H.12 | RISKY command + user modifies to still-RISKY command | Modified command re-classified; still RISKY triggers HITL again | [spec: design.md edge cases] |
| H.13 | HITL prompt displays: command text, Brain reasoning, risk explanation, tier that triggered | All four elements present in the prompt | [spec: design.md approval prompt format] |
| H.14 | RISKY command + user approves | `exit_code` is non-null (command was executed) | Proves execution actually happened after approval |
| H.15 | RISKY command + user denies | `exit_code: null`, `output: ""`, `duration_seconds: null` | Command was never executed |

---

## Section 6 — Response Contract

### P1 — SHOULD PASS

Every response must conform to the documented schema regardless of outcome path.

**Field presence (always present):**

| ID | Scenario | Assert Field Present | Rationale |
|----|----------|---------------------|-----------|
| R.01 | SAFE command completes | `status`, `classification`, `action`, `output`, `stderr`, `exit_code`, `output_metadata`, `audit_id` | [spec: design.md response table — all fields] |
| R.02 | RISKY command denied | `status`, `classification`, `action`, `output`, `stderr`, `exit_code`, `output_metadata`, `audit_id` | Same contract for all paths |
| R.03 | FORBIDDEN command | `status`, `classification`, `action`, `output`, `stderr`, `exit_code`, `error`, `output_metadata`, `audit_id` | Same contract; `error` field populated |
| R.04 | Empty command | `status`, `error`, `audit_id` | Minimal error response |

**Field value constraints:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| R.10 | `status` is always one of: `"completed"`, `"denied"`, `"error"` | [spec: design.md — response table] |
| R.11 | `classification` is always one of: `"FORBIDDEN"`, `"SAFE"`, `"RISKY"` | [spec: design.md — response table] |
| R.12 | `action` is always one of: `"auto_approved"`, `"user_approved"`, `"user_denied"`, `"user_modified"`, `"user_abandoned"` | [spec: design.md — response table] |
| R.13 | `error` is one of: `"forbidden_command"`, `"timeout"`, `"redaction_failure"`, `"empty_command"`, or `null` | [spec: design.md — response table] |
| R.14 | When `status` is `"completed"`, `exit_code` is an integer (not null) | Command was executed |
| R.15 | When `status` is `"denied"` or `"error"`, `exit_code` is `null` | Command was not executed |
| R.16 | When `classification` is `"SAFE"`, `action` is `"auto_approved"` | SAFE commands bypass HITL |
| R.17 | When `classification` is `"FORBIDDEN"`, `status` is `"error"` and `error` is `"forbidden_command"` | FORBIDDEN always errors |
| R.18 | `duration_seconds` is `null` when command was not executed; is a non-negative float when executed | [spec: design.md] |
| R.19 | `duration_seconds` is present even on timeout (shows elapsed time before kill) | [spec: design.md — "Present even on timeout"] |
| R.20 | `audit_id` is a non-empty string for every response | [spec: design.md — "Always present"] |

---

## Section 7 — Execution (Stage 3)

### P0 — MUST PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| E.01 | Commands are executed via argument list, never `shell=True` — verify the subprocess call uses list form | [spec: architecture.md Stage 3 — "never shell=True"] |
| E.02 | A command that exceeds the configured timeout is killed; response has `status: "error"`, `error: "timeout"` | [spec: architecture.md — error handling, timeout] |
| E.03 | stdout and stderr are captured separately — a command that writes to both returns distinct `output` and `stderr` fields | [spec: architecture.md Stage 3] |

### P1 — SHOULD PASS

| ID | Input Command | Expected | Rationale |
|----|---------------|----------|-----------|
| E.10 | A SAFE command that exits with code 0 | `status: "completed"`, `exit_code: 0` | Normal success path |
| E.11 | A SAFE command that exits with non-zero code | `status: "completed"`, `exit_code: N` (N != 0), stderr captured | [spec: architecture.md — "non-zero exit is not an error from the Shell's perspective"] |
| E.12 | A non-existent command (approved via HITL) | `status: "completed"`, `exit_code: 127`, stderr contains "command not found" | [spec: architecture.md — OS-level error] |
| E.13 | A command that produces no output | `status: "completed"`, `output: ""`, `exit_code: 0` | [spec: design.md edge cases — empty output is valid] |

---

## Section 8 — Output Processing: Truncation

### P1 — SHOULD PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| TR.01 | JSON array with 312 items | Output shows first 3 + last 1 items + truncation message `"[truncated: showing 4 of 312 items]"` | [spec: design.md — JSON array rule] |
| TR.02 | JSON array with 3 items (under threshold) | Output is unmodified; `truncation_applied: false` | Below threshold — no truncation |
| TR.03 | JSON object with nested arrays exceeding threshold | Top-level keys preserved; nested arrays truncated (first 3 + last 1) | [spec: design.md — JSON object rule] |
| TR.04 | JSON object deeper than 3 levels | Capped at depth 3 | [spec: design.md — "cap object depth at 3 levels"] |
| TR.05 | Tabular text with 500 rows | Header row + first N data rows + `"[truncated: showing N of 500 rows]"` | [spec: design.md — tabular rule] |
| TR.06 | Log/stream text with 2000 lines | First 20 lines + last 10 lines + `"[truncated: N lines omitted]"` | [spec: design.md — log/stream rule] |
| TR.07 | Binary output (non-UTF-8 bytes) | Replaced entirely with `"[binary output: N bytes, not displayed]"` | [spec: design.md — binary rule] |
| TR.08 | Output under threshold (~200 lines and ~4000 tokens) | No truncation applied; `truncation_applied: false` | Below both thresholds |

### P0 — MUST PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| TR.09 | stderr is **never** truncated — a 10,000-line stderr is returned in full | [spec: design.md — "Stderr: NEVER truncated"] |

### P2 — GOOD TO PASS

**Truncation metadata accuracy:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| TR.20 | `truncation_applied` is `true` when truncation occurred, `false` otherwise | [spec: design.md metadata example] |
| TR.21 | `total_lines` matches the actual line count of the raw output | Metadata accuracy |
| TR.22 | `lines_shown` matches the number of lines in the truncated output | Metadata accuracy |
| TR.23 | For JSON arrays: `items_total` and `items_shown` are present and accurate | [spec: design.md metadata example] |
| TR.24 | `output_type` correctly identifies: `"json_array"`, `"json_object"`, `"tabular"`, `"log_stream"`, `"binary"` | Format detection accuracy |

---

## Section 9 — Output Processing: Privacy Redaction

### P0 — MUST PASS

These tests verify that secrets never reach the Brain or persist in audit logs.

| ID | Input Pattern in Output | Expected After Redaction | Rationale |
|----|------------------------|--------------------------|-----------|
| S.01 | `api-key: sk-abc123def456` | `api-key: [REDACTED]` | [spec: design.md — API keys] |
| S.02 | `password=MyS3cret!` | `password=[REDACTED]` | [spec: design.md — Passwords] |
| S.03 | `passwd=hunter2` | `passwd=[REDACTED]` | Password variant |
| S.04 | `pwd=secret123` | `pwd=[REDACTED]` | Password variant |
| S.05 | `Authorization: Bearer eyJ0eXAiOiJKV1Q...` | `Authorization: Bearer [REDACTED]` | [spec: design.md — Bearer tokens] |
| S.06 | `Server=tcp:mydb.database.windows.net;Password=abc` | `[REDACTED_CONNECTION_STRING]` | [spec: design.md — Connection strings] |
| S.07 | `-----BEGIN RSA PRIVATE KEY-----\nMIIE...` | `[REDACTED_PRIVATE_KEY]` | [spec: design.md — Private keys] |
| S.08 | `"subscriptionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"` | `"subscriptionId": "[REDACTED]"` | [spec: design.md — Azure subscription IDs] |
| S.09 | `AccountKey=SGVsbG8gV29ybGQ=` | `AccountKey=[REDACTED]` | [spec: design.md — Azure storage keys] |
| S.10 | `?sv=2021-06-08&ss=b&srt=co&sp=rwdlacup&se=2023-01-01&st=2022-01-01&spr=https&sig=abc123` | `[REDACTED_SAS_TOKEN]` | [spec: design.md — SAS tokens] |

**Redaction ordering and safety invariants:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| S.20 | Redaction happens AFTER truncation — verify by having a secret at line 500 of a 2000-line output; after truncation (which keeps first 20 + last 10), the secret at line 500 is not in the truncated output and thus not a leak risk | [spec: design.md — "Redaction happens AFTER truncation"] |
| S.21 | If redaction regex throws an exception, the response is `status: "error"`, `error: "redaction_failure"`; raw output is NOT returned | [spec: architecture.md — redaction failure is fail-closed] |
| S.22 | The audit log contains the same redacted output as the response to the Brain — no "raw" version stored anywhere | [spec: design.md — "Unredacted output is never persisted"] |
| S.23 | `az login` output is classified SAFE but output is redacted (tokens, tenant IDs) | [spec: design.md edge cases — `az login`] |

### P2 — GOOD TO PASS

**Redaction metadata:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| S.30 | `redactions_applied` is `true` when redactions occurred, `false` otherwise | [spec: design.md metadata] |
| S.31 | `redaction_count` matches the number of redactions performed | Metadata accuracy |
| S.32 | `redaction_categories` lists the correct categories that matched | Metadata accuracy |
| S.33 | When no secrets are present, `redaction_categories` is an empty array | Clean baseline |

---

## Section 10 — Topology Anonymization (Opt-In)

### P1 — SHOULD PASS

**Default behavior (anonymization OFF):**

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| A.01 | Anonymization disabled (default); output contains `10.0.0.5` | `10.0.0.5` passes through unmodified | [spec: design.md — "Default: OFF"] |
| A.02 | Anonymization disabled; output contains `/subscriptions/abc/resourceGroups/prod-rg` | Resource ID passes through unmodified | Default OFF |
| A.03 | Anonymization disabled; `output_metadata` does not contain `anonymization_applied` or it is `false` | No anonymization metadata when disabled | Clean baseline |

**Enabled behavior:**

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| A.10 | Anonymization enabled; output contains `10.0.0.5` | Replaced with `[INTERNAL_IP_1]` | [spec: design.md — RFC 1918 10.x.x.x] |
| A.11 | Anonymization enabled; output contains `172.16.0.1` | Replaced with `[INTERNAL_IP_N]` | [spec: design.md — RFC 1918 172.16-31.x.x] |
| A.12 | Anonymization enabled; output contains `172.31.255.254` | Replaced (upper bound of 172.16-31 range) | RFC 1918 boundary |
| A.13 | Anonymization enabled; output contains `192.168.1.100` | Replaced with `[INTERNAL_IP_N]` | [spec: design.md — RFC 1918 192.168.x.x] |
| A.14 | Anonymization enabled; output contains `10.0.1.0/24` | Replaced with `[INTERNAL_SUBNET_1]` | [spec: design.md — Subnet CIDRs] |
| A.15 | Anonymization enabled; output contains `/subscriptions/abc123/resourceGroups/prod-rg` | Replaced with `[AZURE_RESOURCE_1]` | [spec: design.md — Azure Resource IDs] |

**Consistent mapping within a session:**

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| A.20 | Same IP `10.0.0.5` appears in two separate commands within one session | Both replaced with the same placeholder `[INTERNAL_IP_N]` (same N) | [spec: design.md — "Same IP always maps to same placeholder within a session"] |
| A.21 | Two different IPs `10.0.0.5` and `10.0.0.6` appear | Different placeholders: `[INTERNAL_IP_1]` and `[INTERNAL_IP_2]` | Distinct IPs get distinct placeholders |
| A.22 | Same IP appears twice in the same output | Both occurrences replaced with identical placeholder | Consistency within single output |

**Negative — must NOT anonymize:**

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| A.30 | Anonymization enabled; output contains `8.8.8.8` (public IP) | `8.8.8.8` passes through unmodified | Only RFC 1918 ranges are anonymized |
| A.31 | Anonymization enabled; output contains `172.32.0.1` (not RFC 1918) | Passes through unmodified | 172.32.x.x is outside the 172.16-31 range |
| A.32 | Anonymization enabled; output contains `172.15.255.255` (not RFC 1918) | Passes through unmodified | 172.15.x.x is below the 172.16 lower bound |

### P2 — GOOD TO PASS

**Ordering and metadata:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| A.40 | Anonymization runs AFTER standard redaction — a secret inside an IP-like string is redacted first, then anonymization processes the remaining output | [spec: design.md — "Anonymization runs AFTER standard redaction"] |
| A.41 | When enabled, `output_metadata` contains `anonymization_applied: true` | [spec: design.md metadata] |
| A.42 | When enabled, `output_metadata` contains `anonymization_mappings_count: N` where N matches the number of distinct anonymized values | [spec: design.md metadata] |
| A.43 | Audit record contains `anonymization_applied: true` when enabled | [spec: design.md audit schema] |
| A.44 | Audit record contains `anonymization_applied: false` when disabled | [spec: design.md audit schema] |

---

## Section 11 — Audit Trail

### P1 — SHOULD PASS

**Record schema completeness (every field present with correct types):**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| AU.01 | A completed SAFE command produces an audit record with all 18 fields from the schema | [spec: design.md audit schema] |
| AU.02 | `timestamp` is a valid ISO 8601 string | [spec: design.md — ISO 8601] |
| AU.03 | `session_id` is consistent across all records in a session | Session identity |
| AU.04 | `sequence` is monotonically increasing (each record's sequence = previous + 1) | [spec: design.md — "Monotonically increasing"] |
| AU.05 | `classification` in audit matches classification in response to Brain | Response/audit consistency |
| AU.06 | `status` in audit matches `status` in response to Brain | Response/audit consistency |
| AU.07 | `tier_triggered` is `0` for FORBIDDEN, `1`/`2`/`3` for RISKY, `null` for SAFE | [spec: design.md — tier_triggered field] |
| AU.08 | `environment` is `"local"` for local commands, `"azure"` for `az` commands | [spec: design.md — environment field] |
| AU.09 | `output_summary` is first 200 chars of processed output | [spec: design.md] |
| AU.10 | `modified_command` is non-null only when user chose Modify | [spec: design.md] |
| AU.11 | `user_decision` is `null` for SAFE commands | [spec: design.md] |
| AU.12 | `anonymization_applied` field is present in every audit record | [spec: design.md — new field] |

**Storage:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| AU.20 | Audit file is JSONL format (one JSON object per line; each line is valid JSON) | [spec: design.md — JSONL] |
| AU.21 | Audit file is named `shell_audit_{session_id}.jsonl` | [spec: design.md — file naming] |
| AU.22 | Records are append-only — running 5 commands produces exactly 5 lines (no overwrites, no deletions) | [spec: design.md — append-only] |
| AU.23 | One file per session — two separate sessions produce two files | [spec: design.md — one file per session] |

**Logging behavior by command type:**

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| AU.30 | Empty command (`""`) | No audit record written | [spec: design.md — "empty/malformed commands are not logged"] |
| AU.31 | FORBIDDEN command (`rm -rf /`) | Audit record IS written | [spec: design.md — "Forbidden commands ARE logged"] |
| AU.32 | SAFE command | Audit record written | Standard behavior |
| AU.33 | RISKY command (denied) | Audit record written | All non-empty commands are logged |
| AU.34 | RISKY command (approved) | Audit record written | Standard behavior |

### P2 — GOOD TO PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| AU.40 | Audit log write failure does not block command execution — command still returns results | [spec: architecture.md — "Log warning, do NOT block command execution"] |
| AU.41 | Audit log write failure is logged to stderr | [spec: architecture.md — "audit gap is logged to stderr"] |

---

## Section 12 — Error Handling

### P0 — MUST PASS

| ID | Scenario | Expected Response | Rationale |
|----|----------|-------------------|-----------|
| ER.01 | Empty command `""` | `status: "error"`, `error: "empty_command"` | [spec: architecture.md error table] |
| ER.02 | Whitespace-only command `"   "` | `status: "error"`, `error: "empty_command"` | [spec: design.md edge cases — whitespace only] |
| ER.03 | Redaction regex throws exception | `status: "error"`, `error: "redaction_failure"`, output is empty (raw output never exposed) | [spec: architecture.md — fail closed] |

### P1 — SHOULD PASS

| ID | Scenario | Expected Response | Rationale |
|----|----------|-------------------|-----------|
| ER.10 | Command times out | `status: "error"`, `error: "timeout"`, `duration_seconds` is non-null | [spec: architecture.md error table] |
| ER.11 | Command returns non-zero exit code | `status: "completed"` (not `"error"`), `exit_code: N` | [spec: architecture.md — "non-zero exit is not an error from Shell's perspective"] |
| ER.12 | OS command not found (exit code 127) | `status: "completed"`, `exit_code: 127`, stderr contains "command not found" | [spec: architecture.md error table] |
| ER.13 | HITL timeout (no user response) | `status: "denied"`, `action: "user_abandoned"` | [spec: design.md — fail-closed] |
| ER.14 | FORBIDDEN command | `status: "error"`, `error: "forbidden_command"`, `classification: "FORBIDDEN"` | [spec: architecture.md error table] |

---

## Section 13 — Input Validation & Edge Cases

### P1 — SHOULD PASS

| ID | Input | Expected | Rationale |
|----|-------|----------|-----------|
| EC.01 | Command with embedded newlines: `"ping 8.8.8.8\nrm -rf /"` | -> RISKY (Tier 3) | [spec: design.md edge cases — "Treat as dangerous pattern"] |
| EC.02 | Missing `reasoning` field in request | Reject with error (field is required) | [spec: design.md — `reasoning` is required] |
| EC.03 | Missing `command` field in request | Reject with error (field is required) | [spec: design.md — `command` is required] |
| EC.04 | `command` is `null` | Same as empty command — `status: "error"`, `error: "empty_command"` | Null is equivalent to empty |

### P2 — GOOD TO PASS

| ID | Input | Expected | Rationale |
|----|-------|----------|-----------|
| EC.10 | Command with extremely long arguments (10,000 chars) | Shell does not crash; if OS rejects, return OS error | [spec: design.md edge cases — OS-level limits apply] |
| EC.11 | Command string with Unicode characters | Classified normally; no crash | Robustness |
| EC.12 | `reasoning` field is an empty string `""` | Allowed (field is present but empty) — classify and execute normally | `reasoning` is required to be present, not necessarily non-empty |
| EC.13 | `reasoning` field is 10,000 characters | Accepted without error; recorded in audit log | No length limit specified |

---

## Section 14 — Pipeline Ordering & Integration

### P0 — MUST PASS

These tests verify that the four-stage pipeline executes in strict sequence and that the four-tier classification evaluates in order.

**Stage ordering:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| PL.01 | A FORBIDDEN command never reaches Stage 2 (HITL) — mock HITL has zero invocations | [spec: architecture.md — "FORBIDDEN short-circuits to error response without entering Stage 2"] |
| PL.02 | A FORBIDDEN command never reaches Stage 3 (Execute) — no subprocess is spawned | FORBIDDEN never executes |
| PL.03 | A denied command never reaches Stage 3 (Execute) — no subprocess is spawned | Denial prevents execution |
| PL.04 | Stage 4 (Process Output) runs only after Stage 3 returns — output processing never sees partial output from a running subprocess | Sequential pipeline |
| PL.05 | Audit log is written after output processing is complete — the audit record contains processed (truncated + redacted) output, not raw | [spec: design.md lifecycle diagram] |

**Tier ordering:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| PL.10 | Tier 0 is evaluated before Tier 1 — a command that matches both Tier 0 (forbidden) and Tier 1 (not in allowlist) returns FORBIDDEN, not RISKY | [spec: architecture.md — "Tier 0 is checked first"] |
| PL.11 | Tier 1 short-circuits on non-allowlisted commands — a command not in the allowlist is immediately RISKY without evaluating Tier 2 or 3 | [spec: design.md Tier 1 — "immediately classified RISKY — no further tiers are evaluated"] |
| PL.12 | Tier 3 overrides Tier 1+2 SAFE — `sudo ping 8.8.8.8` passes Tier 1 (ping is allowed) but Tier 3 catches `sudo` and classifies RISKY | [spec: design.md Tier 3 — "override any SAFE classification from Tiers 1 and 2"] |

**Output processing ordering:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| PL.20 | Truncation runs before redaction | [spec: design.md — "truncate first, then redact"] |
| PL.21 | If anonymization is enabled, it runs after redaction (order: truncate -> redact -> anonymize) | [spec: design.md — "Anonymization runs AFTER standard redaction"] |

---

## Section 15 — Dual Environment

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| DE.01 | `ping 8.8.8.8` is classified through the same pipeline as `az vm list` — same function entry point, same four-tier check | [spec: architecture.md — "Same classification pipeline for both"] |
| DE.02 | The response `environment` field is `"local"` for `ping 8.8.8.8` | [spec: design.md audit — environment field] |
| DE.03 | The response `environment` field is `"azure"` for `az vm list` | [spec: design.md audit — environment field] |
| DE.04 | `pcap_forensics.py --input file.pcap` has environment `"local"` | Analysis tool = local |

---

## Section 16 — Subprocess Safety

### P0 — MUST PASS

| ID | Assertion | How to Verify | Rationale |
|----|-----------|---------------|-----------|
| SS.01 | No code path calls `subprocess.run()` or `subprocess.Popen()` with `shell=True` | Static analysis / grep of source code | [spec: architecture.md — "never shell=True"] |
| SS.02 | Commands are passed as argument lists (arrays), not as raw strings to a shell | Code inspection; mock subprocess and assert call signature | [spec: architecture.md — "split into argument vectors"] |

### P3 — MAY FAIL

These require real subprocess execution and depend on the OS environment.

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| SS.10 | Execute `ping -c 1 127.0.0.1` (SAFE, real execution) | `status: "completed"`, `exit_code: 0`, output contains ping statistics | Real subprocess smoke test |
| SS.11 | Execute `dig google.com` (SAFE, real execution) | `status: "completed"`, output contains DNS response | Requires network access |
| SS.12 | Execute a command with a 1-second timeout that sleeps for 5 seconds | `status: "error"`, `error: "timeout"`, subprocess is killed | Timeout enforcement with real process |
| SS.13 | Execute `netstat -an` (SAFE, real execution) | `status: "completed"`, output contains network connections | OS-dependent output format |

---

## Section 17 — Concurrent Request Handling

### P2 — GOOD TO PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| CO.01 | Two requests sent simultaneously to `execute()` | Requests are serialized — second request blocks until first completes, or caller receives an error | [spec: design.md edge cases — "Not supported. The Shell processes one command at a time, synchronously"] |
| CO.02 | Audit log `sequence` numbers remain monotonically increasing under concurrent calls | No gaps, no duplicates | Sequential integrity |

---

## Section 18 — Interaction Combinations (Cross-Cutting)

### P0 — MUST PASS

Compound scenarios that test multiple features interacting.

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| X.01 | FORBIDDEN command + anonymization enabled | FORBIDDEN error returned; anonymization is irrelevant (no output to anonymize); audit record has `anonymization_applied: false` (or true — it's a session setting) | FORBIDDEN short-circuits before output processing |
| X.02 | SAFE command + output contains both a secret (Bearer token) and an internal IP + anonymization enabled | Both the secret is redacted AND the IP is anonymized; correct ordering preserved | Truncate -> Redact -> Anonymize |
| X.03 | RISKY command + user approves + command times out | `status: "error"`, `error: "timeout"` — approval does not prevent timeout | Timeout overrides approval |
| X.04 | RISKY command + user modifies to a FORBIDDEN command | Modified command is re-classified; hits Tier 0; returns FORBIDDEN error | Re-classification must check Tier 0 |
| X.05 | SAFE `az login` command + output contains bearer tokens | Classified SAFE; output is redacted; `redaction_categories` includes bearer tokens | [spec: design.md special cases] |

### P1 — SHOULD PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| X.10 | Large JSON array output (500 items) with a secret in item 250 + anonymization enabled | Truncated to 4 items; secret in item 250 is not in truncated output; remaining IPs anonymized | Truncation removes most data; redaction/anonymization process only the visible remainder |
| X.11 | RISKY command + user modifies + modified command is SAFE + output requires truncation | `action: "user_modified"`, truncation applied, metadata accurate | Full pipeline traversal after modification |
| X.12 | Non-zero exit code + stderr contains a password | `status: "completed"`, stderr has password redacted | Stderr is redacted but never truncated |
| X.13 | FORBIDDEN command + audit log write failure | FORBIDDEN error returned to Brain; warning logged to stderr; no crash | Audit failure is non-blocking even for FORBIDDEN |

---

## Appendix A — Test Infrastructure Requirements

### Mocks and Stubs

| Component | Mock Strategy |
|-----------|---------------|
| HITL prompt | Stub that returns configurable responses: approve, deny, modify, timeout, exception |
| Subprocess execution | For unit tests: mock `subprocess.run()` to return controlled stdout/stderr/exit_code. For integration tests (P3): use real subprocess |
| Audit log filesystem | Temp directory per test; verify file contents after each test |
| Clock/timestamps | Fixed or controllable clock for deterministic `timestamp` and `duration_seconds` values |
| Anonymization mapping | Verify via a session-scoped dictionary; inspect internal state between commands |

### Test Data Fixtures

| Fixture | Purpose |
|---------|---------|
| `output_json_array_large.json` | 500-item JSON array for truncation tests |
| `output_json_nested.json` | Deeply nested JSON object (5+ levels) for depth-cap tests |
| `output_tabular_500rows.txt` | 500-row tabular output for tabular truncation tests |
| `output_log_2000lines.txt` | 2000-line log output for log/stream truncation tests |
| `output_with_secrets.txt` | Output containing all 8 redaction pattern categories |
| `output_with_ips.txt` | Output containing RFC 1918 IPs, public IPs, subnets, and Azure resource IDs |
| `output_binary.bin` | Non-UTF-8 binary content |

### Coverage Requirements

| Priority | Required Coverage |
|----------|-------------------|
| P0 (MUST PASS) | 100% of test cases pass on every run |
| P1 (SHOULD PASS) | 100% of test cases pass before merge |
| P2 (GOOD TO PASS) | Tracked; 90%+ before production |
| P3 (MAY FAIL) | Run in CI; failures logged but do not block |

---

## Appendix B — Test Count Summary

| Section | P0 | P1 | P2 | P3 | Total |
|---------|----|----|----|----|-------|
| 1. Tier 0: Forbidden | 23 | — | — | — | 23 |
| 2. Tier 1: Allowlist | 6 | 46 | — | — | 52 |
| 3. Tier 2: Azure Verbs | — | 27 | — | — | 27 |
| 4. Tier 3: Dangerous Patterns | 4 | — | — | — | 4 |
| 4. Tier 3: Shell Evasion | 6 | — | — | — | 6 |
| 4. Tier 3: Destructive Ops | 9 | — | — | — | 9 |
| 4. Tier 3: Chaining | 6 | — | — | — | 6 |
| 5. HITL Gate | 6 | 6 | — | — | 12 |
| 6. Response Contract | — | 14 | — | — | 14 |
| 7. Execution | 3 | 4 | — | — | 7 |
| 8. Truncation | 1 | 8 | 5 | — | 14 |
| 9. Redaction | 14 | — | 4 | — | 18 |
| 10. Anonymization | — | 12 | 5 | — | 17 |
| 11. Audit Trail | — | 17 | 2 | — | 19 |
| 12. Error Handling | 3 | 5 | — | — | 8 |
| 13. Edge Cases | — | 4 | 4 | — | 8 |
| 14. Pipeline Ordering | 7 | — | — | — | 7 |
| 15. Dual Environment | — | 4 | — | — | 4 |
| 16. Subprocess Safety | 2 | — | — | 4 | 6 |
| 17. Concurrency | — | — | 2 | — | 2 |
| 18. Cross-Cutting | 5 | 4 | — | — | 9 |
| **Totals** | **95** | **151** | **22** | **4** | **272** |
