# Test Plan — security-rule-inspector

> Document order: **Requirements → Architecture → Design → Test Plan (this document) → Code**
> Design source: `security-rule-inspector/docs/design.md`

---

## 1. Scope

### In scope

| Layer | Component | What is tested |
|---|---|---|
| Unit | `nsg_engine.py` | `evaluate_verdict()`, `audit()`, `_evaluate_gate()`, `_match_rule()`, `_is_unresolvable()`, `_is_wildcard_address()`, `_collect_shadows()`, `_detect_permissive()` — pure function correctness across all 10 fixtures and adversarial inputs |
| Unit | `nsg_preprocessor.py` | Envelope parsing (all 4 formats), gate identification, rule normalisation, shadow detection, port/address canonicalisation |
| Unit | `providers.py` | `LocalShell.run()`, `AzureNSGProvider.get_nic_name()`, `AzureNSGProvider.get_effective_nsg()`, `_call_with_retry()`, `_classify_error()`, `is_throttle()` |
| Unit | `security_rule_inspector.py` | CLI argument parsing, `_detect_mode()`, `_validate_traffic_tuple()`, `_enforce_session_prefix()`, `_check_collision()`, `_ensure_audit_dir()`, `_render_verdict_table()`, `_render_audit_table()` |
| Integration | Pipeline Stages 2–5 | Full pipeline with `MockNSGProvider` injection; artifact written at correct path; `args.traffic` propagation; exit codes |
| Integration | Ghost Agent handler | `_run_security_rule_inspector_handler()` — subprocess arg construction, artifact path construction, structured result extraction, INDETERMINATE handling |

### Explicitly out of scope

| Capability | Reason |
|---|---|
| Live Azure subscription calls | All Azure I/O is mocked; no credentials required |
| AI-generated narrative | Tool is deterministic; no AI component |
| ASG membership resolution | Intentionally excluded; UNRESOLVABLE is the specified behaviour |
| Remediation execution | Read-only tool; no mutations |
| Multi-subscription scope | Out of architectural scope |
| OS firewall (iptables/nftables) | Separate tool (`detect_config_drift`) |

---

## 2. Test Environment Requirements

- Python 3.10+
- `ipaddress` module (stdlib)
- `pytest` with `unittest.mock` for subprocess patching
- All 10 fixtures present at `security-rule-inspector/fixtures/`
- `nsg_preprocessor.py` present at `security-rule-inspector/nsg_preprocessor.py` (copied from skill)
- Writable temp directory for artifact lifecycle tests (`tmp_path` pytest fixture)
- No Azure credentials, no network access required

---

## 3. Fixture Index

Fixture contents verified by direct inspection. Values used verbatim in test assertions.

| Fixture | Gates | Custom rules | Primary scenario |
|---|---|---|---|
| fx-01 | subnet (1 custom) + NIC (1 custom) | subnet: Allow Tcp 443 p=200; NIC: Allow Tcp 443 src=10.0.0.0/16 p=300 | Happy path — both gates ALLOW inbound |
| fx-02 | subnet (1 custom) + NIC (1 custom) | subnet: Deny Tcp 5432 p=100; NIC: Allow Tcp 5432 src=10.0.1.0/24 p=1000 | Subnet deny overrides NIC allow — inbound |
| fx-03 | subnet (1 custom) + NIC (1 custom) | subnet: Allow Tcp 8080 p=100; NIC: Deny Tcp 8080 p=200 | Both inbound gates evaluated; NIC denies after subnet allows |
| fx-04 | subnet (3 custom) + NIC (0 custom) | subnet: Deny All `*`→`*` 0-65535 p=100; Allow Tcp 443 p=200; Allow Tcp 22 src=10.0.0.0/8 p=300 | Shadow detection — deny-all at 100 shadows 200 and 300 |
| fx-05 | subnet (1 custom) + NIC (1 custom) | subnet: Allow Tcp 22 dst=10.0.3.0/24 p=200; NIC: Deny Tcp 22 dst=10.0.3.0/24 p=100 | Outbound gate order — NIC first |
| fx-06 | subnet only (2 custom) | subnet: Allow Tcp 80 src=10.0.1.0/24 p=100; Deny All Internet p=200 | Single gate — no NIC NSG |
| fx-07 | subnet (4 custom) + NIC absent | Custom rules use AzureMonitor, Storage, AzureCloud, Internet service tags | Service tag UNRESOLVABLE flagging |
| fx-08 | subnet (3 custom) + NIC absent | Deny Tcp 8085 src=192.168.0.0/16 p=50; Allow Tcp 8080-8090 src=10.0.0.0/8 p=100; Allow Tcp 3000-3010 src=10.0.5.0/24 p=110 | Port range matching |
| fx-09 | subnet (0 custom) + NIC (0 custom) | Default rules only on both gates | Default-only evaluation; no custom policy |
| fx-10 | subnet (8 custom) + NIC (3 custom) | Complex: AzureLoadBalancer src, CIDR src/dst, port ranges, deny-all at 500, Storage service tag | Production scenario — shadows, service tag, layered rules |

---

## 4. Test Categories

| Tag | Meaning |
|---|---|
| GATE-ORDER | Correct Azure dual-gate evaluation sequence per direction |
| MATCH | Rule matching logic — protocol, address, port |
| SHORT-CIRCUIT | Correct Gate 2 skip when Gate 1 is DENY or INDETERMINATE |
| SHADOW | Shadow detection and correct decisive-rule attribution |
| INDETERMINATE | UNRESOLVABLE rule propagation; INDETERMINATE in verdict and artifact |
| AUDIT | Audit mode findings — shadows, permissive rules, default-only gates |
| PREPROCESS | Envelope parsing, rule normalisation, gate identification |
| PROVIDER | Subprocess execution, retry policy, error classification |
| CLI | Argument parsing, mode detection, session ID, collision |
| PIPELINE | End-to-end Stage 2–5 with mock provider |
| HANDLER | Ghost Agent integration |
| DANGER | Adversarial — silent wrong verdict if broken |

DANGER-tagged tests are the highest-priority failures. A wrong result in GATE-ORDER or SHORT-CIRCUIT allows traffic that should be blocked, or blocks traffic that should be allowed, with no indication to the engineer.

---

## 5. Unit Tests — `nsg_engine.py`

**Test setup:** Load each fixture via `nsg_preprocessor.preprocess(fixture_path)`. Pass `result` to `evaluate_verdict()` or `audit()` directly. No mocking required — these are pure functions.

---

### 5.1 `evaluate_verdict()` — fixture-based verdict correctness

#### T-EV-01 — Both gates ALLOW inbound (fx-01) [GATE-ORDER, MATCH]

- Traffic: `src=10.0.0.5`, `dst=10.0.1.10`, `dst_port=443`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `allow-https-inbound` (p=200, Tcp, src=`*`, port=443) → match → ALLOW
- Gate 2 (NIC): `allow-https-nic` (p=300, Tcp, src=10.0.0.0/16, port=443) → 10.0.0.5 ∈ 10.0.0.0/16 → ALLOW
- Assert: `final_verdict == "ALLOW"`, `gate1.verdict == "ALLOW"`, `gate2.verdict == "ALLOW"`, `gate2.evaluated == True`

#### T-EV-02 — NIC gate INDETERMINATE due to VirtualNetwork tag (fx-01) [MATCH, GATE-ORDER, INDETERMINATE]

- Traffic: `src=192.168.1.1`, `dst=10.0.1.10`, `dst_port=443`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `allow-https-inbound` (src=`*`) → ALLOW (wildcard source matches)
- Gate 2 (NIC): `allow-https-nic` (p=300, src=10.0.0.0/16) → 192.168.1.1 ∉ 10.0.0.0/16 → False → continue
  Next: `AllowVnetInBound` (p=65000, src=VirtualNetwork) → `VirtualNetwork` is unexpanded in this fixture → `_is_unresolvable` returns True → gate2 = INDETERMINATE
- Gate1=ALLOW + Gate2=INDETERMINATE → `final_verdict = INDETERMINATE` (propagation table D15)
- Assert: `final_verdict == "INDETERMINATE"`, `gate1.verdict == "ALLOW"`, `gate2.verdict == "INDETERMINATE"`, `gate2.evaluated == True`
- Assert: `gate2.unresolvable_rule.name == "AllowVnetInBound"`, `gate2.decisive_rule is None`

  _Note: The engine never reaches `DenyAllInBound` (p=65500) because evaluation halts at the first UNRESOLVABLE rule._

#### T-EV-03 — Subnet deny short-circuits NIC (fx-02) [SHORT-CIRCUIT, GATE-ORDER]

- Traffic: `src=10.0.1.5`, `dst=10.0.2.10`, `dst_port=5432`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `ghost-demo-subnet-block-5432` (p=100, Deny Tcp port=5432) → DENY
- Assert: `final_verdict == "DENY"`, `gate2.evaluated == False`, `gate2.skip_reason == "PRIOR_GATE_DENY"`
- Assert: `gate2.decisive_rule is None`

#### T-EV-04 — Subnet port-specific deny skipped; VirtualNetwork tag causes INDETERMINATE (fx-02) [MATCH, INDETERMINATE]

- Traffic: `src=10.0.1.5`, `dst=10.0.2.10`, `dst_port=22`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `ghost-demo-subnet-block-5432` (p=100, Deny, Tcp, port=5432) → port 22 ≠ 5432 → False → continue
  Next: `AllowVnetInBound` (p=65000, src=VirtualNetwork) → `VirtualNetwork` is unexpanded in this fixture → UNRESOLVABLE → gate1 = INDETERMINATE
- Gate 2 not evaluated (gate1=INDETERMINATE per short-circuit rule)
- Assert: `final_verdict == "INDETERMINATE"`, `gate2.evaluated == False`, `gate2.skip_reason == "PRIOR_GATE_INDETERMINATE"`
- Assert: `gate1.unresolvable_rule.name == "AllowVnetInBound"`

  _Note: Tests that unexpanded VirtualNetwork tag at p=65000 triggers INDETERMINATE correctly, preventing incorrect propagation to Gate 2._

#### T-EV-05 — Both gates evaluated inbound; NIC denies last (fx-03) [GATE-ORDER, MATCH]

- Traffic: `src=1.2.3.4`, `dst=10.0.1.20`, `dst_port=8080`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `allow-web-traffic` (p=100, Allow Tcp port=8080, src=`*`) → ALLOW
- Gate 2 (NIC): `deny-port-8080-nic` (p=200, Deny Tcp port=8080, src=`*`) → DENY
- Assert: `final_verdict == "DENY"`, `gate1.verdict == "ALLOW"`, `gate2.verdict == "DENY"`, `gate2.evaluated == True`
- Assert: `gate2.decisive_rule.name == "deny-port-8080-nic"`

#### T-EV-06 — Shadowed allow not selected; deny-all wins (fx-04) [SHADOW, MATCH, DANGER]

- Traffic: `src=1.2.3.4`, `dst=10.0.1.5`, `dst_port=443`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `deny-all-custom` (p=100, Deny All, src=`*`, dst=`*`, port=0-65535) → protocol All matches Tcp; port 0-65535 contains 443; source `*` → DENY
- Assert: `final_verdict == "DENY"`, `gate1.decisive_rule.name == "deny-all-custom"`
- Assert: NO rule named `allow-https-inbound` appears as `gate1.decisive_rule` (it is shadowed and must never be cited)
- Assert: `gate2.evaluated == False`, `gate2.skip_reason == "PRIOR_GATE_DENY"`

#### T-EV-07 — Outbound: NIC evaluated first, subnet ALLOW irrelevant (fx-05) [GATE-ORDER, SHORT-CIRCUIT, DANGER]

- Traffic: `src=10.0.1.10`, `dst=10.0.3.5`, `dst_port=22`, `proto=Tcp`, `direction=Outbound`
- Gate 1 is NIC (outbound): `deny-lateral-movement` (p=100, Deny Tcp dst=10.0.3.0/24 port=22) → 10.0.3.5 ∈ 10.0.3.0/24 → DENY
- Assert: `final_verdict == "DENY"`, `gate1.gate == "nic"`
- Assert: `gate2.evaluated == False`, `gate2.skip_reason == "PRIOR_GATE_DENY"`
- Assert: the subnet's `allow-ssh-to-backend` (p=200) NEVER appears in the result as a decisive rule
- _DANGER: if gate order is reversed for outbound, subnet is evaluated first → ALLOW, masking the NIC deny_

#### T-EV-08 — Single gate, no NIC NSG (fx-06) [GATE-ORDER, MATCH]

- Traffic: `src=10.0.1.10`, `dst=10.0.1.5`, `dst_port=80`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `allow-http-from-web-tier` (p=100, Allow Tcp src=10.0.1.0/24 port=80) → ALLOW
- Gate 2 (NIC): absent from fixture → empty rule list → ALLOW, `decisive_rule = null`
- Assert: `final_verdict == "ALLOW"`, `gate1.verdict == "ALLOW"`, `gate2.decisive_rule is None`

  Cross-check — port not allowed:
- Traffic: `src=10.0.1.10`, `dst=10.0.1.5`, `dst_port=3306`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet):
  1. `allow-http-from-web-tier` (p=100, Tcp, port=80): port 3306 ≠ 80 → False → continue
  2. `deny-direct-internet-inbound` (p=200, All, src=Internet): `Internet` is an unexpanded service tag in this fixture → `_is_unresolvable` returns True → gate1 = INDETERMINATE at p=200
- Evaluation halts at p=200; `AllowVnetInBound` (p=65000) and `DenyAllInBound` (p=65500) are never reached
- Assert: `final_verdict == "INDETERMINATE"`, `gate1.unresolvable_rule.name == "deny-direct-internet-inbound"`

#### T-EV-09 — Default deny for internet source, no custom rules (fx-09) [MATCH]

- Traffic: `src=203.0.113.50`, `dst=10.0.1.5`, `dst_port=443`, `proto=Tcp`, `direction=Inbound`
- Gate 1 (subnet): `AllowVnetInBound` (65000, VirtualNetwork) → UNRESOLVABLE; INDETERMINATE
- Assert: `final_verdict == "INDETERMINATE"` (VirtualNetwork tag unresolvable)

  Cross-check with wildcard source:
- Traffic: `src=203.0.113.50`, same fixture but evaluate against `DenyAllInBound` (65500, src=`*`, dst=`*`, port=0-65535)
- Inject a synthetic rule set where VirtualNetwork is pre-expanded to CIDRs that 203.0.113.50 is NOT in, then DenyAllInBound fires → DENY
- Assert: `decisive_rule.name == "DenyAllInBound"`, `decisive_rule.is_default == True`

#### T-EV-10 — Port range matching at boundaries (fx-08) [MATCH]

All sub-cases: `proto=Tcp`, `direction=Inbound`. fx-08 has a subnet-only NSG (no NIC entry).

- T-EV-10a: `src=10.0.0.5`, `dst_port=8080` → `deny-port-8085-override` (p=50, src=192.168.0.0/16): 10.0.0.5 ∉ 192.168.0.0/16 → False; `allow-api-port-range` (p=100, src=10.0.0.0/8, range 8080-8090): 10.0.0.5 ∈ 10.0.0.0/8, 8080 ∈ [8080,8090] → ALLOW (lower bound inclusive)
- T-EV-10b: `src=10.0.0.5`, `dst_port=8090` → same path → ALLOW (upper bound inclusive)
- T-EV-10c: `src=10.0.0.5`, `dst_port=8079` → no match on p=100 (8079 < 8080); falls through defaults → INDETERMINATE at AllowVnetInBound (p=65000, src=VirtualNetwork unexpanded)
- T-EV-10d: `src=10.0.0.5`, `dst_port=8091` → no match on p=100 (8091 > 8090); same path as T-EV-10c → INDETERMINATE
- T-EV-10e: `src=192.168.1.5`, `dst_port=8085` → `deny-port-8085-override` (p=50, src=192.168.0.0/16): 192.168.1.5 ∈ 192.168.0.0/16, port=8085 → DENY at p=50, BEFORE p=100 allow fires

  _Note: T-EV-10c and T-EV-10d reach INDETERMINATE (not DENY) because AllowVnetInBound at p=65000 has unexpanded VirtualNetwork tag, stopping evaluation before DenyAllInBound at p=65500._

---

### 5.2 `_match_rule()` — detailed matching logic

#### T-MR-01 — Protocol wildcard "All" matches Tcp [MATCH]

- Rule: `protocol="All"`, src=`*`, dst=`*`, port=`*`; Traffic: proto=Tcp
- Assert: returns `True`

#### T-MR-02 — Protocol wildcard "*" matches Udp [MATCH]

- Rule: `protocol="*"`, src=`*`, dst=`*`, port=`*`; Traffic: proto=Udp
- Assert: returns `True`

#### T-MR-03 — Protocol mismatch — Tcp rule does not match Udp [MATCH, DANGER]

- Rule: `protocol="Tcp"`, src=`*`, dst=`*`, port=`*`; Traffic: proto=Udp
- Assert: returns `False`
- _DANGER: if protocol check is skipped, a Tcp-only deny blocks Udp traffic_

#### T-MR-04 — Source CIDR containment — exact boundary [MATCH]

- Rule: `source_address="10.0.1.0/24"`, dst=`*`, port=`*`, proto=Tcp; Traffic: src=10.0.1.255
- Assert: returns `True` (last address in /24)

#### T-MR-05 — Source CIDR — just outside [MATCH, DANGER]

- Rule: `source_address="10.0.1.0/24"`; Traffic: src=10.0.2.0
- Assert: returns `False` (10.0.2.0 is NOT in 10.0.1.0/24)

#### T-MR-06 — Comma-separated source address — first value matches [MATCH]

- Rule: `source_address="10.0.0.0/8, 192.168.0.0/16"`; Traffic: src=10.1.2.3
- Assert: returns `True` (10.1.2.3 ∈ 10.0.0.0/8, found before 192.168.0.0/16 is checked)

#### T-MR-07 — Comma-separated source address — second value matches [MATCH]

- Rule: `source_address="10.0.0.0/8, 192.168.0.0/16"`; Traffic: src=192.168.1.5
- Assert: returns `True` (first CIDR no match, second matches)

#### T-MR-08 — Unresolvable service tag stops evaluation [INDETERMINATE, DANGER]

- Rule: `source_address="AzureMonitor"`; Traffic: src=10.0.0.5
- Assert: returns `None` (AzureMonitor is not a CIDR)
- _DANGER: if treated as False, an ALLOW rule using AzureMonitor as destination would be skipped silently_

#### T-MR-09 — Resolvable CIDR before unresolvable tag — match found first [INDETERMINATE]

- Rule: `source_address="10.0.0.0/16, Storage"` (sorted: "10.0.0.0/16" < "Storage"); Traffic: src=10.0.1.5
- Assert: returns `True` (10.0.1.5 ∈ 10.0.0.0/16 matched before Storage encountered)

#### T-MR-10 — Unresolvable tag after CIDR (preprocessor sort places CIDR first) [INDETERMINATE]

- The preprocessor joins multiple address values as `", ".join(sorted(...))`. Since `"1" < "A"` in ASCII, `sorted(["AzureCloud", "10.0.0.0/16"])` produces `["10.0.0.0/16", "AzureCloud"]`.
- Rule: `source_address="10.0.0.0/16, AzureCloud"` (the actual preprocessor output after sorting); Traffic: src=10.0.1.5
- Engine splits on `", "` → evaluates `"10.0.0.0/16"` first → 10.0.1.5 ∈ 10.0.0.0/16 → returns `True` (CIDR matched; AzureCloud never reached)
- Assert: `_match_rule` returns `True`
- Assert inverse: `source_address="AzureCloud"` alone with same traffic → returns `None`
  (verifies that if no CIDR precedes the tag, the result is INDETERMINATE)

#### T-MR-11 — "0-65535" port range treated as wildcard [MATCH]

- Rule: `destination_ports=["0-65535"]`; Traffic: dst_port=443
- Assert: returns `True`

#### T-MR-12 — Wildcard "Any" source address [MATCH]

- Rule: `source_address="Any"`; Traffic: src=203.0.113.1
- Assert: `_is_wildcard_address("Any") == True`; `_match_rule` returns `True`

#### T-MR-13 — "0.0.0.0/0" source is wildcard [MATCH]

- Rule: `source_address="0.0.0.0/0"`; Traffic: src=10.0.0.1
- Assert: `_is_wildcard_address("0.0.0.0/0") == True`; match returns `True`

#### T-MR-14 — Source port always matches regardless of rule value [MATCH]

- Rule: `source_ports=["22"]`, `destination_ports=["*"]`, src=`*`, dst=`*`, proto=Tcp; Traffic: dst_port=80
- Assert: returns `True` (source port is not evaluated; destination port wildcard matches)

---

### 5.3 `_collect_shadows()` — shadow assembly from preprocessor output

#### T-SH-01 — Shadow present; lookup succeeds (fx-04) [SHADOW]

- Load fx-04; preprocessor sets `shadowed_by = "deny-all-custom"` on `allow-https-inbound`
- Call `_collect_shadows(inbound_rules, gate="subnet", direction="Inbound")`
- Assert: result contains `ShadowedRule(rule.name="allow-https-inbound", shadowed_by.name="deny-all-custom", gate="subnet", direction="Inbound")`

#### T-SH-02 — Multiple shadows in same gate (fx-04) [SHADOW]

- fx-04 subnet inbound: deny-all-custom (p=100) has all wildcards (protocol=All, src=`*`, dst=`*`, ports=0-65535).
  It shadows every lower-priority inbound rule:
  - allow-https-inbound (p=200)
  - allow-ssh-inbound (p=300)
  - AllowVnetInBound (p=65000)
  - AllowAzureLoadBalancerInBound (p=65001)
  - DenyAllInBound (p=65500)
- Assert: `len(result) >= 5`; all shadow entries have `shadowed_by.name == "deny-all-custom"`

#### T-SH-03 — No shadows — empty result [SHADOW]

- Synthetic: all rules have `shadowed_by = None`
- Assert: `_collect_shadows(rules, ...)` returns `[]`

#### T-SH-04 — Orphan `shadowed_by` name (defensive) [SHADOW]

- Synthetic: rule with `shadowed_by = "nonexistent-rule"`, no rule by that name in list
- Assert: result excludes that rule (no entry emitted); parse warning generated

---

### 5.4 `_detect_permissive()` — permissive rule detection

#### T-PM-01 — Custom ALLOW with wildcard source [AUDIT]

- Rule: access=Allow, is_default=False, source_address=`*`, dst=specific, port=443
- Assert: returned as PermissiveRule; `wildcard_dimensions == ["source"]`

#### T-PM-02 — Custom ALLOW with wildcard port [AUDIT]

- Rule: access=Allow, is_default=False, src=10.0.0.0/8, dst=`*`, destination_ports=["*"]
- Assert: returned as PermissiveRule; `wildcard_dimensions` contains `"port"` and `"destination"`

#### T-PM-03 — Default ALLOW with all wildcards — NOT flagged [AUDIT]

- Rule: `AllowVnetOutBound`, is_default=True, src=`*`, dst=`*`, port=`*`
- Assert: NOT returned by `_detect_permissive` (default rules are excluded)

#### T-PM-04 — DENY rule with all wildcards — NOT flagged [AUDIT]

- Rule: `deny-all-custom` from fx-04: access=Deny, source=`*`, dst=`*`, port=0-65535
- Assert: NOT returned (only ALLOW rules are permissive candidates)

#### T-PM-05 — Custom ALLOW with no wildcards — NOT flagged [AUDIT]

- Rule: access=Allow, is_default=False, src=10.0.1.0/24, dst=10.0.2.0/24, port=["443"]
- Assert: NOT returned

---

### 5.5 `audit()` — audit mode findings

#### T-AU-01 — Full audit on fx-04 produces correct shadow findings [AUDIT, SHADOW]

- Call `audit(rule_sets_from_fx04)`
- Assert: `findings.shadowed_rules` contains entries for all five rules shadowed by deny-all-custom:
  `allow-https-inbound` (p=200), `allow-ssh-inbound` (p=300), `AllowVnetInBound` (p=65000),
  `AllowAzureLoadBalancerInBound` (p=65001), `DenyAllInBound` (p=65500)
- Assert: all shadow entries have `gate == "subnet"`, `direction == "Inbound"`, `shadowed_by.name == "deny-all-custom"`
- Assert: NIC gate has no shadowed rules (NIC NSG is defaults-only in fx-04)

#### T-AU-02 — Default-only gates flagged (fx-09) [AUDIT]

- Call `audit(rule_sets_from_fx09)` (both gates, all default rules)
- Assert: `findings.default_only_gates` contains entries for all four rule sets (subnet inbound, subnet outbound, NIC inbound, NIC outbound)
- Assert: all `nsg_absent == False` (NSGs present but only defaults)

#### T-AU-03 — Missing NIC NSG flagged as nsg_absent (fx-06) [AUDIT]

- Call `audit(rule_sets_from_fx06)` (subnet only)
- Assert: `findings.default_only_gates` contains NIC inbound and NIC outbound entries
- Assert: both NIC entries have `nsg_absent == True`

#### T-AU-04 — Permissive rules detected in fx-04 [AUDIT]

- fx-04 subnet inbound contains two custom Allow rules that `_detect_permissive` must flag:
  - `allow-https-inbound` (p=200, Allow, Tcp, src=`*`, dst=`*`, port=443): wildcard source + wildcard destination → permissive; `wildcard_dimensions == ["source", "destination"]`
  - `allow-ssh-inbound` (p=300, Allow, Tcp, src=10.0.0.0/8, dst=`*`, port=22): wildcard destination → permissive; `wildcard_dimensions == ["destination"]`
- `deny-all-custom` (p=100, Deny, wildcard all) — NOT permissive (only Allow rules are permissive candidates)
- Assert: `allow-https-inbound` and `allow-ssh-inbound` both appear in `findings.permissive_rules`
- Assert: `deny-all-custom` does NOT appear in `findings.permissive_rules`
- Assert: wildcard_dimensions for allow-https-inbound is `["source", "destination"]`
- Assert: wildcard_dimensions for allow-ssh-inbound is `["destination"]`

  _Note: A rule can appear in both `shadowed_rules` and `permissive_rules` simultaneously — the audit surfaces all issues regardless of reachability._

#### T-AU-05 — Rule inventory sorted by priority ascending [AUDIT]

- Call `audit(rule_sets_from_fx10)` — complex fixture with many rules
- Assert: `rule_sets.inbound.gate1.rules` list has priorities in ascending order
- Assert: no rule at position i has a lower priority number than a rule at position i-1

#### T-AU-06 — Gate1/Gate2 assignment is direction-dependent [GATE-ORDER, AUDIT]

- Call `audit(rule_sets_from_fx05)` (outbound focus fixture)
- Assert: `rule_sets.outbound.gate1.gate == "nic"` and `rule_sets.outbound.gate2.gate == "subnet"`
- Assert: `rule_sets.inbound.gate1.gate == "subnet"` and `rule_sets.inbound.gate2.gate == "nic"`

---

## 6. Unit Tests — `nsg_preprocessor.py`

#### T-PP-01 — Format 1 (`"value"` wrapper) parses correctly [PREPROCESS]

- Load fx-01 (uses `"value"` wrapper); call `preprocess(path)`
- Assert: `gate_count == 2`, no `"error"` key

#### T-PP-02 — Format 2 (`"networkSecurityGroups"` wrapper) parses correctly [PREPROCESS]

- Synthesise a fixture wrapping the same entries under `"networkSecurityGroups"` instead of `"value"`
- Assert: `gate_count == 2`, same rules extracted as Format 1

#### T-PP-03 — Format 4 (single NSG, `"effectiveSecurityRules"` at top level) [PREPROCESS]

- Synthesise: `{"effectiveSecurityRules": [...]}` with no wrapper
- Assert: `gate_count == 1`, rules parsed correctly

#### T-PP-04 — Gate identification by association type [PREPROCESS]

- Load fx-01; inspect `result["gates"]`
- Assert: one entry has `association_type == "subnet"`, `gate == "subnet-nsg"`
- Assert: one entry has `association_type == "networkInterface"`, `gate == "nic-nsg"`

#### T-PP-05 — Association absent — fallback label and parse warning [PREPROCESS]

- Synthesise entry with no `"association"` key
- Assert: `gate == "nsg-1"` (positional fallback), `association_type == "unknown"`, parse warning emitted

#### T-PP-06 — Rule normalisation — plural port array preferred over singular [PREPROCESS]

- Synthesise rule with `destinationPortRange = "443"` AND `destinationPortRanges = ["80", "443"]`
- Assert: `destination_ports == ["80", "443"]` (plural preferred)

#### T-PP-07 — Rule normalisation — expanded address preferred over plain [PREPROCESS]

- Synthesise rule with `sourceAddressPrefix = "VirtualNetwork"` AND `expandedSourceAddressPrefix = ["10.0.0.0/16", "10.1.0.0/16"]`
- Assert: `source_address == "10.0.0.0/16, 10.1.0.0/16"` (expanded, sorted, joined)

#### T-PP-08 — Protocol "All" preserved (not converted to "*") [PREPROCESS]

- Rule with `protocol = "All"`
- Assert: `NsgRuleObject.protocol == "All"`

#### T-PP-09 — Rules sorted by priority ascending within gate [PREPROCESS]

- Load fx-08 (has rules at p=50, p=100, p=110 out of natural file order)
- Assert: `gates[0]["inbound_rules"][0].priority == 50`
- Assert: `gates[0]["inbound_rules"][1].priority == 100`
- Assert: `gates[0]["inbound_rules"][2].priority == 110`

#### T-PP-10 — Shadow detection sets `shadowed_by` on shadowed rules [PREPROCESS]

- Load fx-04; inspect `result["gates"]` for subnet gate, inbound rules
- Assert: rule with name `allow-https-inbound` (p=200) has `shadowed_by == "deny-all-custom"` (p=100)
- Assert: rule `deny-all-custom` itself has `shadowed_by == None`

#### T-PP-11 — Shadow detection NOT triggered for partial-overlap rules [PREPROCESS]

- fx-04: `deny-all-custom` (All, p=100) vs `allow-ssh-inbound` (Tcp 22 from 10.0.0.0/8, p=300)
- The deny-all IS all wildcards (protocol All, ports 0-65535, src *, dst *) → shadows allow-ssh-inbound → `shadowed_by` set
- Separately: synthesise a Tcp-only deny-rule (not All) before an allow rule for Udp → should NOT shadow
- Assert: Udp allow rule's `shadowed_by == None` when higher-priority rule is Tcp-only

#### T-PP-12 — File not found → error dict [PREPROCESS]

- Call `preprocess("/nonexistent/path.json")`
- Assert: `"error"` in result, no `gate_count` key

#### T-PP-13 — Invalid JSON → error dict [PREPROCESS]

- Write a file containing `{invalid json}`, call `preprocess(path)`
- Assert: `"error"` in result

#### T-PP-14 — Empty entries list → gate_count 0 with parse warning [PREPROCESS]

- Synthesise `{"value": []}` (empty array)
- Assert: `gate_count == 0`, `"error"` NOT in result, parse warning contains `"No NSG entries found"`

---

## 7. Unit Tests — `providers.py`

#### T-PR-01 — `LocalShell.run()` returns stdout on exit 0 [PROVIDER]

- Mock `subprocess.run` to return exit code 0, stdout `'{"key": "value"}'`
- Assert: `run(["az", ...])` returns `'{"key": "value"}'`

#### T-PR-02 — `LocalShell.run()` raises `ProviderError` on non-zero exit [PROVIDER]

- Mock `subprocess.run` to return exit code 1, stderr `"error message"`
- Assert: raises `ProviderError` with message containing `"error message"`

#### T-PR-03 — `LocalShell.run()` raises `ProviderError` on timeout [PROVIDER]

- Mock `subprocess.run` to raise `subprocess.TimeoutExpired`
- Assert: raises `ProviderError` with `"timeout"` in message

#### T-PR-04 — `LocalShell.run()` uses argument vector, not shell=True [PROVIDER]

- Capture the `subprocess.run` call kwargs
- Assert: `shell` kwarg is absent or `False`

#### T-PR-05 — `is_throttle()` — known patterns [PROVIDER]

- Assert: `is_throttle("Too Many Requests") == True`
- Assert: `is_throttle("429") == True`
- Assert: `is_throttle("throttling") == True`
- Assert: `is_throttle("rate limit exceeded") == True`
- Assert: `is_throttle("AuthorizationFailed") == False`
- Assert: `is_throttle("ResourceNotFound") == False`

#### T-PR-06 — `_call_with_retry()` retries on throttle, max 5 attempts [PROVIDER]

- Mock shell to return throttle stderr on first 4 calls, then succeed on 5th
- Assert: succeeds; mock called exactly 5 times
- Assert backoff: each call has increasing delay (verify sleep call args)

#### T-PR-07 — `_call_with_retry()` raises `ThrottleExhausted` after 5 throttle failures [PROVIDER]

- Mock shell to always return throttle stderr
- Assert: raises `ThrottleExhausted` after 5 calls; `attempts == 5`

#### T-PR-08 — `_classify_error()` raises `RBACError` for AuthorizationFailed [PROVIDER]

- Call `_classify_error("AuthorizationFailed: ... effectiveNetworkSecurityGroups/action", context="...")`
- Assert: raises `RBACError`; message contains permission name

#### T-PR-09 — `_classify_error()` raises `VMNotFoundError` for ResourceNotFound [PROVIDER]

- Call `_classify_error("ResourceNotFound: VM 'test-vm' not found", context="az vm show")`
- Assert: raises `VMNotFoundError`

#### T-PR-10 — `get_nic_name()` selects NIC by primary=True [PROVIDER]

- Mock `_call_with_retry` to return VM JSON with two NICs: one `primary: false`, one `primary: true`
- Assert: returns the name from the `primary: true` entry

#### T-PR-11 — `get_nic_name()` falls back to single entry when no primary flag [PROVIDER]

- Mock response: one NIC entry, no `primary` key
- Assert: returns the name from that single entry (no NICResolutionError)

#### T-PR-12 — `get_nic_name()` raises `NICResolutionError` — multiple NICs, none primary [PROVIDER]

- Mock response: two NIC entries, neither has `primary: true`
- Assert: raises `NICResolutionError`

---

## 8. Unit Tests — `security_rule_inspector.py`

#### T-CLI-01 — Mode detection: all five → verdict [CLI]

- Set all five traffic flags; call `_detect_mode(args)`
- Assert: returns `"verdict"`

#### T-CLI-02 — Mode detection: none → audit [CLI]

- Set no traffic flags; call `_detect_mode(args)`
- Assert: returns `"audit"`

#### T-CLI-03 — Mode detection: partial tuple → exit 2 [CLI, DANGER]

- Test each combination of 1, 2, 3, and 4 of the five traffic flags
- Assert: each partial set calls `sys.exit(2)` and prints the five-flag requirement message

#### T-CLI-04 — `_validate_traffic_tuple()` normalises protocol case [CLI]

- Input: `proto="TCP"` → Assert: `TrafficTuple.protocol == "Tcp"`
- Input: `proto="udp"` → Assert: `TrafficTuple.protocol == "Udp"`
- Input: `proto="*"` → Assert: `TrafficTuple.protocol == "*"`
- Input: `proto="icmp"` → Assert: `TrafficTuple.protocol == "Icmp"`

#### T-CLI-05 — `_validate_traffic_tuple()` normalises direction case [CLI]

- Input: `direction="INBOUND"` → Assert: `TrafficTuple.direction == "Inbound"`
- Input: `direction="outbound"` → Assert: `TrafficTuple.direction == "Outbound"`

#### T-CLI-06 — `_validate_traffic_tuple()` rejects invalid IP [CLI]

- Input: `src_ip="not-an-ip"` → Assert: `sys.exit(2)`, message contains `"Invalid IP address"`

#### T-CLI-07 — `_validate_traffic_tuple()` rejects port out of range [CLI]

- Input: `dst_port=0` → exit 2; `dst_port=65536` → exit 2; `dst_port=65535` → valid; `dst_port=1` → valid

#### T-CLI-08 — `_enforce_session_prefix()` prepends nsg_ when absent [CLI]

- Input: `"myrun"` → `"nsg_myrun"`
- Input: `"nsg_myrun"` → `"nsg_myrun"` (unchanged)
- Input: `"nsg_"` → `"nsg_"` (starts with prefix, unchanged)

#### T-CLI-09 — `_check_collision()` exits 2 when artifact exists [CLI]

- Write `nsg_test123_raw.json` to tmp dir
- Call `_check_collision("nsg_test123", tmp_dir)`
- Assert: `sys.exit(2)`, message contains session ID and audit_dir path

#### T-CLI-10 — `_check_collision()` passes when no artifacts exist [CLI]

- Empty tmp dir
- Assert: `_check_collision("nsg_test123", tmp_dir)` returns normally (no exit)

#### T-CLI-11 — `_ensure_audit_dir()` creates directory if absent [CLI]

- Path does not exist; call `_ensure_audit_dir(path)`
- Assert: directory created; returns `Path` object

#### T-CLI-12 — `--nic-name` override sets nic_name on args [CLI]

- Pass `--nic-name override-nic`; verify `args.nic_name == "override-nic"` after parse

---

## 9. Integration Tests — Pipeline Stages 2–5

All integration tests use `MockNSGProvider` injected via `_run_pipeline(args, provider=mock)`.
No subprocess calls; no real Azure access.

#### T-INT-01 — Verdict mode: raw artifact written after collect [PIPELINE]

- Inject mock returning fx-01 data; run in verdict mode
- Assert: `{session_id}_raw.json` exists in tmp audit_dir after pipeline
- Assert: content is valid JSON with `"value"` key

#### T-INT-02 — Verdict mode: verdict artifact written, stdout printed [PIPELINE]

- Inject mock returning fx-01 data; run verdict mode with TCP 443 inbound
- Assert: `{session_id}_verdict.json` exists; `final_verdict == "ALLOW"`
- Assert: stdout contains `"Final verdict"` and `"ALLOW"`

#### T-INT-03 — Audit mode: audit artifact written, stdout printed [PIPELINE]

- Inject mock returning fx-10 data; run audit mode
- Assert: `{session_id}_audit.json` exists; `mode == "audit"` in artifact
- Assert: stdout contains `"FINDINGS"` section

#### T-INT-04 — Identity fields added by orchestrator, not engine [PIPELINE]

- Run verdict mode on any fixture
- Assert: `verdict_artifact["vm_name"]` == supplied `--vm-name` value
- Assert: `verdict_artifact["nic_name"]` == NIC name returned by mock provider
- Assert: `verdict_artifact["session_id"]` starts with `"nsg_"`

#### T-INT-05 — parse_warnings forwarded into artifact [PIPELINE]

- Use a fixture that triggers preprocessor warnings (e.g., missing association → gate type unknown)
- Assert: `verdict_artifact["parse_warnings"]` is non-empty

#### T-INT-06 — `--nic-name` override: `get_nic_name()` not called [PIPELINE]

- Pass `--nic-name preresolved-nic` to pipeline; mock provider records calls
- Assert: `get_nic_name` never called; `get_effective_nsg` called once with `"preresolved-nic"`

#### T-INT-07 — RBACError → exit 2, no artifacts written [PIPELINE]

- Mock `get_effective_nsg` to raise `RBACError("effectiveNetworkSecurityGroups/action")`
- Assert: pipeline returns exit code 2
- Assert: `{session_id}_raw.json` does NOT exist (no partial write)

#### T-INT-08 — Preprocessor gate_count=0 → exit 2, raw artifact retained [PIPELINE]

- Inject mock returning `{"value": []}` (empty value array)
- Assert: pipeline returns exit code 2
- Assert: raw artifact EXISTS (was written before preprocessing failed)
- Assert: no verdict or audit artifact written

#### T-INT-09 — Collision check before any Azure call [PIPELINE]

- Pre-create `{session_id}_raw.json` in tmp audit_dir
- Assert: pipeline returns exit code 2 immediately; mock provider never called

#### T-INT-10 — args.traffic reaches Stage 4 in verdict mode [PIPELINE]

- Run verdict mode; inject mock; capture argument passed to `nsg_engine.evaluate_verdict`
- Assert: `traffic.dst_port` matches the `--dst-port` CLI argument

---

## 10. Ghost Agent Handler Tests

#### T-GH-01 — Handler constructs subprocess args correctly [HANDLER]

- Invoke `_run_security_rule_inspector_handler()` with verdict-mode config
- Capture the subprocess call
- Assert: `--vm-name`, `--resource-group`, `--src-ip`, `--dst-ip`, `--dst-port`, `--proto`, `--direction`, `--session-id`, `--audit-dir` all present
- Assert: no `--nic-name` flag when NIC override not set

#### T-GH-02 — Handler reads verdict artifact, not stdout [HANDLER]

- Mock subprocess to return exit 0; pre-create a verdict artifact at the deterministic path
- Assert: handler parses the file, not stdout

#### T-GH-03 — Handler returns INDETERMINATE without proceeding [HANDLER]

- Pre-create verdict artifact with `final_verdict == "INDETERMINATE"` and populated `unresolvable_rules`
- Assert: handler result includes `final_verdict == "INDETERMINATE"` and `unresolvable_rules`
- Assert: handler does NOT set any key indicating NSG is clean or that host-firewall check should proceed

#### T-GH-04 — Handler checks file existence before parse on exit 2 [HANDLER]

- Mock subprocess to return exit code 2; no artifact at expected path
- Assert: handler raises a structured error or returns an error dict; does NOT raise `FileNotFoundError` uncaught

#### T-GH-05 — Handler uses correct artifact path for audit mode [HANDLER]

- Invoke with audit-mode config (no traffic tuple)
- Assert: artifact path used is `{AUDIT_DIR}/{session_id}_audit.json`
  (session_id already starts with `nsg_` — no additional prefix is prepended)
- Assert: NOT `_verdict.json`
- Assert: NOT `nsg_{session_id}_audit.json` (which would be a double prefix)

#### T-GH-06 — Handler generates nsg_ session ID; prefix not doubled [HANDLER]

- Capture the session ID passed as `--session-id` in subprocess args
- Assert: session ID starts with `"nsg_"` exactly once (no `"nsg_nsg_"`)

---

## 11. Adversarial Test Cases

These tests exercise failure modes that produce incorrect verdicts without obvious errors. Each is tagged DANGER.

#### T-ADV-01 — Outbound gate reversal produces silent wrong verdict [DANGER, GATE-ORDER]

**Scenario:** fx-05. Outbound traffic from 10.0.1.10 to 10.0.3.5:22.
NIC NSG (Gate 1 for outbound) DENIES. Subnet NSG (Gate 2) allows.

If the engine evaluates gates in the wrong order (subnet first), it returns ALLOW.
If it evaluates NIC first, it returns DENY.

- Assert: `final_verdict == "DENY"`, `gate1.gate == "nic"`, `gate2.evaluated == False`
- Assert: no verdict of ALLOW for this traffic tuple against this fixture

#### T-ADV-02 — Shadowed allow rule cited as decisive rule [DANGER, SHADOW]

**Scenario:** fx-04. Traffic TCP 443 inbound. `deny-all-custom` (p=100) shadows `allow-https-inbound` (p=200).

If the engine evaluates rules in wrong order (descending instead of ascending priority), it could match the allow rule first.

- Assert: `gate1.decisive_rule.name == "deny-all-custom"` (not `allow-https-inbound`)
- Assert: `allow-https-inbound` appears only in `shadowed_rules`, never in `gate1.decisive_rule`

#### T-ADV-03 — "All" protocol passes through as match for Tcp traffic [DANGER, MATCH]

**Scenario:** Synthesise a rule with `protocol="All"` and specific port 22. Traffic is Tcp/22.

If `"All"` is not treated as a wildcard, the Tcp traffic doesn't match the rule and falls to the next rule.

- Assert: `_match_rule(rule_with_protocol_All, tcp_traffic) == True`

#### T-ADV-04 — "0-65535" not treated as port wildcard [DANGER, MATCH]

**Scenario:** Rule has `destination_ports=["0-65535"]`. Traffic dst_port=443.

If only `"*"` is treated as wildcard and `"0-65535"` is evaluated as a range, 443 must be within [0, 65535]. That would still match but is a different code path.

- Assert: `_match_rule` returns `True` when destination_ports=["0-65535"] and dst_port=443
- Assert: same result when destination_ports=["*"] (identical behaviour)

#### T-ADV-05 — INDETERMINATE propagation: Gate 2 evaluated despite Gate 1 INDETERMINATE [DANGER, INDETERMINATE]

**Scenario:** Gate 1 hits UNRESOLVABLE service tag → INDETERMINATE. Gate 2 would return DENY.

If the engine ignores INDETERMINATE and proceeds to Gate 2, the final verdict becomes DENY, which may or may not be correct — but the verdict is presented as definitive when it is not.

- Synthesise: Gate 1 has one rule with `source_address="Storage"` (unresolvable); Gate 2 has a clear DENY rule
- Assert: `gate2.evaluated == False`, `gate2.skip_reason == "PRIOR_GATE_INDETERMINATE"`
- Assert: `final_verdict == "INDETERMINATE"` — NOT `"DENY"`

#### T-ADV-06 — INDETERMINATE at Gate 2 not lost when Gate 1 ALLOWs [INDETERMINATE]

**Scenario:** Gate 1 returns ALLOW (definitive). Gate 2 hits UNRESOLVABLE.

- Synthesise: Gate 1 matches a wildcard Allow; Gate 2 has a rule with `destination_address="Storage"`
- Assert: `gate1.verdict == "ALLOW"`, `gate2.verdict == "INDETERMINATE"`, `final_verdict == "INDETERMINATE"`

#### T-ADV-07 — Subnet deny at priority 100 blocks traffic; NIC allow at 1000 is irrelevant (fx-02) [GATE-ORDER, DANGER]

**Scenario:** fx-02 inbound port 5432. Subnet blocks at p=100. NIC allows at p=1000.

Engineers investigating this exact scenario often check the NIC NSG (the allow rule is visible) and miss the subnet deny. The tool must name the subnet gate and the subnet rule as the block.

- Traffic: `src=10.0.1.5`, `dst=10.0.2.10`, `dst_port=5432`, `proto=Tcp`, `direction=Inbound`
- Assert: `gate1.gate == "subnet"`, `gate1.verdict == "DENY"`, `gate1.decisive_rule.name == "ghost-demo-subnet-block-5432"`
- Assert: `gate2.evaluated == False`
- Assert: the NIC's `allow-postgres` rule does NOT appear anywhere as the decisive rule

#### T-ADV-08 — Port range off-by-one at boundaries [DANGER, MATCH]

Exact boundary verification (builds on T-EV-10 but explicitly adversarial):

- `dst_port=8079` against range `8080-8090` → assert False (NOT matched)
- `dst_port=8091` against range `8080-8090` → assert False (NOT matched)
- `dst_port=8080` against range `8080-8090` → assert True (lower boundary)
- `dst_port=8090` against range `8080-8090` → assert True (upper boundary)

#### T-ADV-09 — Service tag in destination address INDETERMINATE (fx-07 outbound Storage) [INDETERMINATE, DANGER]

**Scenario:** fx-07 has a rule `allow-storage-outbound` (p=110, Tcp, dst=Storage, port=443). Traffic dst=52.96.0.0 (an actual Azure Storage IP, but we don't know it's in the tag).

- Assert: `_match_rule` for that rule returns `None` (Storage is unresolvable)
- Assert: that rule appears in `unresolvable_rules` in the verdict artifact

#### T-ADV-10 — Gate absent from preprocessor output — treat as empty, not error [GATE-ORDER]

**Scenario:** fx-06 has no NIC NSG. The engine must not crash or skip evaluation; it must treat the NIC gate as empty (ALLOW with `decisive_rule=null`).

- Load fx-06; run `evaluate_verdict` inbound
- Assert: `gate2.evaluated == True` (Gate 2 evaluated), `gate2.verdict == "ALLOW"`, `gate2.decisive_rule is None`
- Assert: no exception raised

#### T-ADV-11 — Gate ordering from preprocessor output order is ignored [GATE-ORDER, DANGER]

**Scenario:** Synthesise a `"value"` array with the NIC NSG entry listed BEFORE the subnet NSG entry. For inbound, subnet must still be Gate 1.

If the engine uses list position instead of `association_type` to assign gate order, the NIC gate becomes Gate 1 for inbound — silently reversing evaluation.

- Assert: `gate1.gate == "subnet"` regardless of the order of entries in `rule_sets["gates"]`

#### T-ADV-12 — `_check_collision` uses correct glob without double prefix [CLI]

- Session ID is `nsg_20260413_100000`
- Pre-create file `nsg_20260413_100000_raw.json` (correct, no double nsg_)
- Assert: `_check_collision("nsg_20260413_100000", audit_dir)` triggers exit 2

- Pre-create file `nsg_nsg_20260413_100000_raw.json` (double prefix, wrong)
- Assert: `_check_collision("nsg_20260413_100000", audit_dir)` passes (no exit) — the double-prefix file is not a collision for this session ID

#### T-ADV-13 — Priority tiebreak: two rules at same priority, first in sorted list wins [MATCH]

- Synthesise two rules at priority 100 (unusual but must not crash): Allow Tcp 443 and Deny Tcp 443
- Assert: one of them is selected as decisive rule (no crash, no indeterminate from priority tie)
- Assert: the selection is deterministic across repeated calls with identical input

#### T-ADV-14 — Complex inbound: AzureLoadBalancer source rule (fx-10) [MATCH, INDETERMINATE]

- fx-10 subnet inbound: `allow-https-from-lb` (p=100, src=AzureLoadBalancer)
- Traffic: src=10.0.5.10 (not AzureLoadBalancer), dst=10.0.2.15, port=443
- AzureLoadBalancer is a service tag. If not expanded (which fx-10 does not expand it), it is UNRESOLVABLE.
- Assert: `_match_rule` returns `None` for the AzureLoadBalancer rule when source_address="AzureLoadBalancer"
- Assert: engine does NOT proceed to next rule; gate verdict is INDETERMINATE

---

## 12. Accuracy Checklist

Before the tool is considered validated, verify each item:

### Core algorithm
- [ ] Inbound: subnet gate always evaluated before NIC gate
- [ ] Outbound: NIC gate always evaluated before subnet gate
- [ ] Gate 1 DENY → Gate 2 not evaluated; `gate2.skip_reason == "PRIOR_GATE_DENY"`
- [ ] Gate 1 INDETERMINATE → Gate 2 not evaluated; `gate2.skip_reason == "PRIOR_GATE_INDETERMINATE"`
- [ ] Gate 1 ALLOW → Gate 2 always evaluated (inbound and outbound)
- [ ] Shadowed rule (fx-04, allow-https-inbound p=200) never cited as decisive rule when deny-all-custom p=100 matches first
- [ ] DENY verdict in Gate 2 after ALLOW in Gate 1 correctly produces final DENY (not ALLOW)

### Matching precision
- [ ] Protocol "All" treated as wildcard (same as "*")
- [ ] Port "0-65535" treated as wildcard (same as "*")
- [ ] Port boundary: 8080 ∈ [8080, 8090] = True; 8079 ∈ [8080, 8090] = False
- [ ] CIDR boundary: 10.0.1.255 ∈ 10.0.1.0/24 = True; 10.0.2.0 ∈ 10.0.1.0/24 = False
- [ ] Address "Any" treated as wildcard (some Azure API versions use this)
- [ ] Address "0.0.0.0/0" treated as wildcard match (not as a CIDR containment check)
- [ ] Comma-separated `source_address` split on `", "` correctly before matching

### Unresolvable / INDETERMINATE
- [ ] Non-standard service tag (Storage, AzureMonitor) in source or destination → UNRESOLVABLE → INDETERMINATE
- [ ] Resolvable CIDR encountered before unresolvable tag → match found; INDETERMINATE not triggered
- [ ] AzureLoadBalancer, VirtualNetwork, Internet unexpanded (tag name not replaced by CIDRs) → UNRESOLVABLE

### Artifacts and exit codes
- [ ] Session ID never has double `nsg_` prefix in artifact filenames
- [ ] Raw artifact written before preprocessing; retained even on preprocessor failure
- [ ] Verdict or audit artifact written only on Stage 4 success; never on Stage 1–3 failure
- [ ] Collision detected before any Azure call; raw artifact absent when collision causes exit 2
- [ ] Exit code 0 ↔ artifact present and usable; exit code 2 ↔ no verdict/audit artifact written

### Ghost Agent integration
- [ ] INDETERMINATE verdict returned to Brain with `unresolvable_rules` populated; no "clean NSG" signal emitted
- [ ] Artifact path constructed deterministically before subprocess runs; no filesystem scan
- [ ] Handler never parses stdout as structured data

---

## 13. Real Fixture Capture

To supplement synthetic fixtures with live Azure output (optional, for manual validation):

```bash
# Capture effective NSG for a specific NIC
az network nic list-effective-nsg \
  --name <nic-name> \
  --resource-group <rg-name> \
  --output json > security-rule-inspector/fixtures/fx-real-<vm-name>.json
```

Store real fixtures with the `fx-real-` prefix to distinguish from synthetic. When a real
fixture is added, document the expected verdict for at least one traffic tuple in a comment
block at the top of the fixture file.

Real fixtures should exercise at least one scenario not covered by synthetic fixtures:
- [ ] NSG with an ASG-based rule (to validate INDETERMINATE path in production)
- [ ] NSG with a non-standard service tag (Storage, Sql, AzureCloud)
- [ ] VM in a subnet with no subnet NSG (single gate)
