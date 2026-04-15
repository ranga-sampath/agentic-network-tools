# Test Plan — effective-route-inspector

> Document order: **Requirements → Architecture → Design → Test Plan (this document) → Code**
> Design source: `effective-route-inspector/docs/design.md`

---

## 1. Scope

### In scope

| Layer | Component | What is tested |
|-------|-----------|----------------|
| Unit | `lpm_engine.py` | `select_route()`, `audit_routes()`, `_check_anomalies()` — pure function correctness, all 15 fixtures, both modes |
| Unit | `route_preprocessor.py` | File parsing, multi-prefix expansion, error paths |
| Unit | `providers.py` | `LocalShell`, `AzureRouteProvider`, retry policy, error classification, `is_throttle()` |
| Unit | `effective_route_inspector.py` | Session ID, CLI argument validation, `_ensure_audit_dir`, `_enforce_session_prefix`, `_render_table` |
| Integration | Pipeline (Stages 2–5) | Full pipeline via `MockRouteProvider` injection seam; artifact lifecycle; exit codes |
| Integration | Ghost Agent handler | `_run_effective_route_inspector_handler()` — subprocess arg construction, verdict read, error dict |

### Explicitly out of scope

| Capability | Reason |
|------------|--------|
| NSG rule evaluation | Different tool (`security_rule_inspector`) |
| AI narrative output | Tool is deterministic; no AI component |
| BGP AS Path tiebreaking | Not in effective route table JSON; `TIED_BGP` is the correct terminal result |
| Fleet / multi-VM scope | Single-VM design contract |
| Drift / baseline comparison | `detect_effective_network_drift` responsibility |
| Real `az` CLI calls | No live Azure subscription required for automated tests |

---

## 2. Test Environment Requirements

- Python 3.10+
- `ipaddress` module (stdlib — always available)
- `pytest` with `unittest.mock` for subprocess patching
- All 15 fixtures present at `fixtures/` relative to the module root
- `route_preprocessor.py` present at `effective-route-inspector/route_preprocessor.py` (copied from skill)
- A writable temp directory for artifact write tests (`tmp_path` pytest fixture)
- No Azure credentials, no network access

---

## 3. Fixture Index

Actual route contents inspected from fixture files. These values are used verbatim in test assertions.

| Fixture | Routes (total) | Active | Invalid | Notes |
|---------|---------------|--------|---------|-------|
| fx-01 | 5 | 5 | 0 | All Default system routes; VNetLocal /16 + three /24s + Internet /0 |
| fx-02 | 4 | 4 | 0 | User UDR `172.16.10.0/24` → VirtualAppliance; Default `172.16.10.0/24` → VnetLocal at same prefix |
| fx-03 | 4 | 4 | 0 | Two VnetPeering /16s + User `0.0.0.0/0` UDR → VirtualAppliance |
| fx-04 | 4 | 4 | 0 | Two User UDRs (192.168.0.0/16, 10.10.0.0/16) → VirtualAppliance |
| fx-05 | 2 | 2 | 0 | Minimal: VNetLocal `10.0.1.0/24` + Internet `0.0.0.0/0` |
| fx-06 | 5 | 5 | 0 | VGW `10.100.0.0/16` + Default `10.100.0.0/16` nextHopType=None (BGP override placeholder); VGW `10.100.50.0/24` |
| fx-07 | 4 | 2 | 2 | Invalid: `10.200.0.0/16` and `10.200.1.0/24` VnetPeering |
| fx-08 | 5 | 5 | 0 | User /32 + /24 + /16 all → VirtualAppliance; VNetLocal /16 + Internet /0 |
| fx-09 | 3 | 3 | 0 | **No `0.0.0.0/0`**; routes: VNetLocal /16, VnetPeering /16, User `192.168.0.0/24` |
| fx-10 | 4 | 4 | 0 | Default `10.30.0.0/16` nextHopType=None (blackhole); Default `10.30.0.0/8` VnetLocal |
| fx-11 | 4 | 4 | 0 | Two multi-prefix entries: `[172.20.0.0/16, 172.20.5.0/24]` and `[10.1.0.0/16, 10.2.0.0/16, 10.3.0.0/16]` |
| fx-12 | 6 | 6 | 0 | Hub-spoke: VGW `192.168.0.0/16` + `192.168.10.0/24`; User `0.0.0.0/0` → VirtualAppliance |
| fx-13 | 7 | 5 | 2 | Invalid: `10.3.5.0/24` and `10.4.0.0/16` VnetPeering |
| fx-14 | 5 | 5 | 0 | **Two identical** VGW `10.50.0.0/24` routes (BGP tie); VGW `10.50.0.0/16` |
| fx-15 | 5 | 5 | 0 | Overlapping UDRs: User /16, /24, /28 all covering `10.0.1.x`; /28 → VnetLocal (override) |

---

## 4. Test Categories

- **LPM**: Algorithm correctness — correct winner selected, correct shadowed candidates, correct `selection_reason`
- **Anomaly**: Correct anomaly detection — BLACKHOLE, INVALID_SHADOW, NVA
- **Null result**: `NO_ROUTE` and `TIED_BGP` declared explicitly; no fabrication
- **False positive / false negative (DANGER)**: Algorithm safety — cases where a wrong result causes a silent security failure
- **Preprocessor**: File parsing, expansion, error path
- **Provider**: subprocess isolation, retry policy, error classification
- **CLI**: Argument parsing, validation, session ID handling
- **Artifact lifecycle**: Raw and verdict files — when written, when absent
- **Pipeline integration**: Full Stage 2–5 via `MockRouteProvider`
- **Ghost Agent handler**: Subprocess construction, verdict read, error dict

---

## 5. Unit Tests — `lpm_engine.py`

**Setup for all LPM tests:** load each fixture through `route_preprocessor.preprocess(fixture_path)`, extract `result["routes"]`, pass to `select_route()` or `audit_routes()`. No mocking required.

---

### 5.1 `select_route()` — single-target mode

#### T-LPM-01 — Basic VNetLocal: LPM selects /24 over /16 and /0 (fx-01)

- **Fixture:** fx-01-basic-vnet-local.json
- **Input:** `dst_ip="10.0.1.50"`
- **Candidates:** `10.0.0.0/16` (/16), `10.0.1.0/24` (/24), `0.0.0.0/0` (/0)
- **Expected:**
  - `result == "WINNER"`
  - `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "10.0.1.0/24"`
  - `winning_route["next_hop_type"] == "VnetLocal"`
  - `winning_route["source"] == "Default"`
  - `len(shadowed_candidates) == 2` — contains `10.0.0.0/16` and `0.0.0.0/0`
  - `anomaly_warnings == []`

#### T-LPM-02 — Source precedence: UDR beats Default at equal /24 prefix (fx-02)

- **Fixture:** fx-02-udr-same-prefix.json
- **Input:** `dst_ip="172.16.10.20"`
- **Candidates at /24:** User `172.16.10.0/24` VirtualAppliance; Default `172.16.10.0/24` VnetLocal
- **Expected:**
  - `result == "WINNER"`
  - `selection_reason == "SOURCE_PRECEDENCE"`
  - `winning_route["prefix"] == "172.16.10.0/24"`
  - `winning_route["source"] == "User"`
  - `winning_route["next_hop_type"] == "VirtualAppliance"`
  - `len(shadowed_candidates) == 3` — contains Default `172.16.10.0/24` (lost at Step 3), `172.16.0.0/16` and `0.0.0.0/0` (lost at Step 2)
  - `"NVA_WARNING"` in `anomaly_warnings[0]`

#### T-LPM-03 — LPM absolute: VnetPeering /16 beats User UDR /0 (fx-03)

This is the "NVA bypass" failure mode. A /0 UDR exists to route all traffic through a firewall. VNet peering adds /16 routes that are more specific — spoke traffic bypasses the firewall regardless of source precedence.

- **Fixture:** fx-03-lpm-beats-udr.json
- **Input:** `dst_ip="10.2.5.10"`
- **Candidates:** Default `10.2.0.0/16` VnetPeering (/16); User `0.0.0.0/0` VirtualAppliance (/0)
- **Expected:**
  - `result == "WINNER"`
  - `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "10.2.0.0/16"`
  - `winning_route["source"] == "Default"` — Default wins over User because LPM is applied first
  - `winning_route["next_hop_type"] == "VnetPeering"` — NOT VirtualAppliance
  - `anomaly_warnings == []` — no NVA warning (winner is not VirtualAppliance)
  - `shadowed_candidates` contains User `0.0.0.0/0`

⚠️ **DANGER:** If source precedence were applied before LPM, the UDR at /0 would win (User tier 1 > Default tier 3). This would declare traffic goes to the NVA — but it actually bypasses it. A wrong result here produces a false "route is correct" verdict in a firewall bypass investigation.

#### T-LPM-04 — NVA UDR: winner is VirtualAppliance, NVA warning emitted (fx-04)

- **Fixture:** fx-04-nva-udr.json
- **Input:** `dst_ip="192.168.5.10"`
- **Candidates:** User `192.168.0.0/16` VirtualAppliance (/16); Default `0.0.0.0/0` Internet (/0)
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "192.168.0.0/16"`, `source == "User"`
  - `"NVA_WARNING"` in `anomaly_warnings[0]`

#### T-LPM-05a — Minimal table: catch-all /0 wins for public destination (fx-05)

- **Fixture:** fx-05-minimal-routes.json
- **Input:** `dst_ip="8.8.8.8"`
- **Candidates:** Default `0.0.0.0/0` Internet only (`10.0.1.0/24` does not cover 8.8.8.8)
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "0.0.0.0/0"`, `winning_route["is_zero_route"] == True`
  - `shadowed_candidates == []`, `anomaly_warnings == []`

#### T-LPM-05b — Minimal table: VNetLocal /24 beats /0 for private destination (fx-05)

- **Fixture:** fx-05-minimal-routes.json
- **Input:** `dst_ip="10.0.1.50"`
- **Expected:**
  - `winning_route["prefix"] == "10.0.1.0/24"`, `selection_reason == "LPM_ONLY"`
  - `shadowed_candidates` contains `0.0.0.0/0`

#### T-LPM-06 — BGP beats Default at equal /16; no blackhole warning on non-winning None route (fx-06)

fx-06 contains Default `10.100.0.0/16` with `nextHopType=None`. This is the system placeholder that Azure inserts when a BGP route overrides a system default. The BGP route wins via source precedence. The None-hop route is NOT the winner, so no BLACKHOLE warning.

- **Fixture:** fx-06-bgp-vs-system.json
- **Input:** `dst_ip="10.100.5.30"`
- **All candidates (Step 1):** VGW `10.100.0.0/16` (/16); Default `10.100.0.0/16` nextHopType=None (/16); Default `0.0.0.0/0` (/0) — `10.0.0.0/16` and `10.100.50.0/24` do not cover this destination
- **After LPM (Step 2):** lpm_winners = [VGW `10.100.0.0/16`, Default `10.100.0.0/16` None]; shadowed = [Default `0.0.0.0/0`]
- **Source precedence (Step 3):** VGW (tier 2) beats Default (tier 3)
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "SOURCE_PRECEDENCE"`
  - `winning_route["source"] == "VirtualNetworkGateway"`
  - `winning_route["next_hop_type"] == "VirtualNetworkGateway"` — NOT "None"
  - `anomaly_warnings == []` — BLACKHOLE check runs only on the winner; None-hop Default is not the winner

⚠️ **DANGER:** If `_check_anomalies` runs on shadowed candidates instead of only the winner, the None-hop Default route would trigger a false BLACKHOLE_WARNING. This would alarm the operator for a route that Azure does not use.

#### T-LPM-06b — BGP /24 wins over /16 candidates for destination in BGP /24 subnet (fx-06)

- **Fixture:** fx-06-bgp-vs-system.json
- **Input:** `dst_ip="10.100.50.10"` — in `10.100.50.0/24` and `10.100.0.0/16` and `0.0.0.0/0`
- **Candidates:** VGW `10.100.50.0/24` (/24); VGW `10.100.0.0/16` (/16); Default `10.100.0.0/16` nextHopType=None (/16); Default `0.0.0.0/0` (/0)
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "10.100.50.0/24"` — single /24 route; no source precedence needed
  - `winning_route["source"] == "VirtualNetworkGateway"`
  - `shadowed_candidates` contains VGW `10.100.0.0/16`, Default `10.100.0.0/16` None, and Default `0.0.0.0/0`
  - `anomaly_warnings == []` — winner is VirtualNetworkGateway hop, not None or VirtualAppliance

---

#### T-LPM-07a — Invalid route excluded; INVALID_SHADOW warning fires for destination in invalid prefix (fx-07)

- **Fixture:** fx-07-invalid-route.json
- **Input:** `dst_ip="10.200.1.50"`
- **Active candidates:** Default `0.0.0.0/0` Internet only (both 10.200.x routes are Invalid)
- **Expected:**
  - `result == "WINNER"`, `winning_route["prefix"] == "0.0.0.0/0"`
  - `anomaly_warnings` contains `INVALID_SHADOW_WARNING` for `10.200.1.0/24` — prefix_length=24 > 0, state=Invalid, 10.200.1.50 ∈ 10.200.1.0/24
  - `anomaly_warnings` also contains `INVALID_SHADOW_WARNING` for `10.200.0.0/16` — prefix_length=16 > 0, state=Invalid, 10.200.1.50 ∈ 10.200.0.0/16
  - `len(anomaly_warnings) == 2`

#### T-LPM-07b — INVALID_SHADOW false positive guard: unrelated Invalid route must NOT trigger warning (fx-07) [DANGER]

- **Fixture:** fx-07-invalid-route.json
- **Input:** `dst_ip="8.8.8.8"`
- **Active candidates:** `0.0.0.0/0` Internet
- **Invalid routes:** `10.200.0.0/16` and `10.200.1.0/24` — both have prefix_length > 0 but **neither contains 8.8.8.8**
- **Expected:**
  - `result == "WINNER"`, `winning_route["prefix"] == "0.0.0.0/0"`
  - `anomaly_warnings == []` — CIDR containment check must prevent false positive

⚠️ **DANGER:** Without the CIDR containment condition in `_check_anomalies`, any table containing an Invalid route would trigger `INVALID_SHADOW_WARNING` for every internet destination. This produces a false alarm on every query to a hub-spoke topology where a disconnected peering exists. The investigation would chase a non-issue.

#### T-LPM-08 — /32 host route: maximum prefix length wins unconditionally (fx-08)

- **Fixture:** fx-08-host-route-slash32.json
- **Input:** `dst_ip="10.5.10.100"`
- **Candidates:** User `10.5.10.100/32` (/32); User `10.5.10.0/24` (/24); User `10.5.0.0/16` (/16); Default `0.0.0.0/0` (/0)
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "10.5.10.100/32"`, `prefix_length == 32`
  - `"NVA_WARNING"` in `anomaly_warnings` (VirtualAppliance hop)
  - `len(shadowed_candidates) == 3`

#### T-LPM-09 — No matching route: NO_ROUTE declared; nothing fabricated (fx-09) [DANGER]

fx-09 has no `0.0.0.0/0`. The destination 203.0.113.1 (TEST-NET-3, RFC 5737) is not covered by any route.

- **Fixture:** fx-09-no-matching-route.json
- **Input:** `dst_ip="203.0.113.1"`
- **Active candidates:** none (all routes cover RFC 1918 space only)
- **Expected:**
  - `result == "NO_ROUTE"`, `selection_reason == "NO_ROUTE"`
  - `winning_route == None`
  - `shadowed_candidates == []`, `anomaly_warnings == []`
  - Function returns immediately after Step 1 — no further processing

⚠️ **DANGER:** If the algorithm fabricates a default route or returns the closest-matching prefix, Ghost Agent Brain would conclude routing is functional. The actual behavior is a silent drop.

#### T-LPM-10 — Blackhole: None hop wins; BLACKHOLE_WARNING emitted (fx-10)

- **Fixture:** fx-10-blackhole-none-hop.json
- **Input:** `dst_ip="10.30.0.50"`
- **Candidates:** Default `10.30.0.0/16` nextHopType=**"None"** (/16); Default `10.30.0.0/8` VnetLocal (/8); Default `0.0.0.0/0` Internet (/0)
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "10.30.0.0/16"`, `winning_route["next_hop_type"] == "None"`
  - `"BLACKHOLE_WARNING"` in `anomaly_warnings[0]`
  - Note: `next_hop_type` is the string `"None"`, not Python `None` / JSON `null`

#### T-LPM-11 — Multi-prefix expansion: /24 beats /16 after expansion (fx-11)

- **Fixture:** fx-11-multi-prefix-entry.json
- **Input:** `dst_ip="172.20.5.10"`
- **Pre-condition:** preprocessor expands `["172.20.0.0/16", "172.20.5.0/24"]` into two `RouteObject`s
- **Candidates:** `172.20.0.0/16` (/16); `172.20.5.0/24` (/24); `0.0.0.0/0` (/0)
- **Expected:**
  - `winning_route["prefix"] == "172.20.5.0/24"`, `selection_reason == "LPM_ONLY"`
  - Both expanded objects appear in route list — verify `route_count` reflects expansion (preprocessor returns 7, not 4)

#### T-LPM-12a — Hub-spoke: BGP /24 beats BGP /16 and UDR /0 for specific on-prem destination (fx-12)

- **Fixture:** fx-12-hub-spoke-production.json
- **Input:** `dst_ip="192.168.10.50"`
- **Candidates:** VGW `192.168.0.0/16` (/16); VGW `192.168.10.0/24` (/24); User `0.0.0.0/0` (/0)
- **Expected:**
  - `winning_route["prefix"] == "192.168.10.0/24"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["source"] == "VirtualNetworkGateway"`
  - `anomaly_warnings == []` — VirtualNetworkGateway hop is not VirtualAppliance

#### T-LPM-12b — Hub-spoke: UDR /0 NVA wins for internet destination (fx-12)

- **Fixture:** fx-12-hub-spoke-production.json
- **Input:** `dst_ip="8.8.8.8"`
- **Candidates:** User `0.0.0.0/0` VirtualAppliance only
- **Expected:**
  - `winning_route["prefix"] == "0.0.0.0/0"`, `winning_route["source"] == "User"`
  - `"NVA_WARNING"` in `anomaly_warnings`

#### T-LPM-12c — Hub-spoke: BGP /16 wins for on-prem destination outside /24 subnet (fx-12)

- **Fixture:** fx-12-hub-spoke-production.json
- **Input:** `dst_ip="192.168.5.30"` — in `192.168.0.0/16` but NOT in `192.168.10.0/24`
- **Expected:**
  - `winning_route["prefix"] == "192.168.0.0/16"`, `selection_reason == "LPM_ONLY"`

#### T-LPM-13a — Disconnected peering: Invalid /24 excluded; INVALID_SHADOW fires (fx-13)

- **Fixture:** fx-13-vnet-peering-routes.json
- **Input:** `dst_ip="10.3.5.20"`
- **Active candidates:** Default `10.3.0.0/16` VnetPeering (/16); Default `0.0.0.0/0` Internet (/0)
- **Invalid routes:** `10.3.5.0/24` (covers 10.3.5.20); `10.4.0.0/16` (does NOT cover 10.3.5.20)
- **Expected:**
  - `winning_route["prefix"] == "10.3.0.0/16"`, `selection_reason == "LPM_ONLY"`
  - `anomaly_warnings` contains `INVALID_SHADOW_WARNING` for `10.3.5.0/24` — prefix_length=24 > 16, 10.3.5.20 ∈ 10.3.5.0/24
  - `anomaly_warnings` does NOT contain warning for `10.4.0.0/16` — two conditions both fail: (1) `prefix_length == 16` is not `> 16` (winner prefix_length), and (2) `10.3.5.20 ∉ 10.4.0.0/16`
  - `len(anomaly_warnings) == 1`

#### T-LPM-13b — INVALID_SHADOW CIDR containment: second Invalid route does not fire for unrelated destination (fx-13)

- **Fixture:** fx-13-vnet-peering-routes.json
- **Input:** `dst_ip="10.4.5.20"` — in `10.4.0.0/16` Invalid but NOT in `10.3.5.0/24` Invalid
- **Active candidates:** Default `0.0.0.0/0` Internet
- **Expected:**
  - `anomaly_warnings` contains `INVALID_SHADOW_WARNING` for `10.4.0.0/16`
  - `anomaly_warnings` does NOT contain warning for `10.3.5.0/24` — 10.4.5.20 ∉ 10.3.5.0/24

#### T-LPM-14a — BGP tie: two identical /24 VGW routes; TIED_BGP must be declared (fx-14) [DANGER]

- **Fixture:** fx-14-bgp-tie-same-prefix.json
- **Input:** `dst_ip="10.50.0.100"`
- **Candidates after LPM:** two VGW `10.50.0.0/24` routes (identical prefix, identical source tier)
- **Expected:**
  - `result == "TIED_BGP"`, `selection_reason == "TIED_BGP"`
  - `winning_route == None`
  - `len(tied_routes) == 2` — both `10.50.0.0/24` VGW routes
  - `shadowed_candidates` contains VGW `10.50.0.0/16` and Default `0.0.0.0/0`
  - `anomaly_warnings == []`

⚠️ **DANGER:** If the algorithm returns the first route from the list instead of declaring TIED_BGP, Ghost Agent Brain will report a definitive winner when Azure's actual selection depends on AS Path length. The wrong path may be reported as confirmed.

#### T-LPM-14b — BGP tie does not affect /16 route for destination outside /24 (fx-14)

- **Fixture:** fx-14-bgp-tie-same-prefix.json
- **Input:** `dst_ip="10.50.5.10"` — in `10.50.0.0/16` but NOT in `10.50.0.0/24`
- **Candidates:** VGW `10.50.0.0/16` (/16); Default `0.0.0.0/0` (/0) — the two `10.50.0.0/24` routes do not cover `10.50.5.10`
- **Expected:**
  - `result == "WINNER"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["prefix"] == "10.50.0.0/16"`
  - `shadowed_candidates` contains Default `0.0.0.0/0`

#### T-LPM-15a — Overlapping UDRs: /28 wins for destination in /28 range (fx-15)

- **Fixture:** fx-15-overlapping-udrs.json
- **Input:** `dst_ip="10.0.1.130"` — in `10.0.1.128/28` (10.0.1.128–10.0.1.143)
- **Candidates:** User `10.0.0.0/16` (/16 VirtualAppliance); User `10.0.1.0/24` (/24 VirtualAppliance); User `10.0.1.128/28` (/28 VnetLocal); Default `10.0.0.0/8` (/8 VnetLocal); Default `0.0.0.0/0` (/0 Internet)
- **Expected:**
  - `winning_route["prefix"] == "10.0.1.128/28"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["next_hop_type"] == "VnetLocal"` — the /28 overrides NVA routing
  - `anomaly_warnings == []` — winner is VnetLocal, not VirtualAppliance
  - `len(shadowed_candidates) == 4`

#### T-LPM-15b — Overlapping UDRs: /24 wins for destination outside /28 (fx-15)

- **Fixture:** fx-15-overlapping-udrs.json
- **Input:** `dst_ip="10.0.1.50"` — in `10.0.1.0/24` but NOT in `10.0.1.128/28`
- **Expected:**
  - `winning_route["prefix"] == "10.0.1.0/24"`, `selection_reason == "LPM_ONLY"`
  - `winning_route["next_hop_type"] == "VirtualAppliance"`
  - `"NVA_WARNING"` in `anomaly_warnings`

---

### 5.2 `audit_routes()` — audit mode

#### T-AUD-01 — Clean system-only table: findings all empty (fx-01)

- **Fixture:** fx-01-basic-vnet-local.json
- **Expected:**
  - `mode == "audit"`, `route_count == 5`, `invalid_route_count == 0`
  - `findings["blackhole_routes"] == []`
  - `findings["nva_routes"] == []`
  - `findings["bgp_routes"] == []`
  - `findings["default_route_present"] == True`
  - `findings["default_route_source"] == "Default"`
  - `routes_by_prefix_length` sorted descending by prefix_length; first entry has `prefix_length == 24`

#### T-AUD-07 — Invalid routes listed separately; active count correct (fx-07)

- **Fixture:** fx-07-invalid-route.json
- **Expected:**
  - `route_count == 4`, `invalid_route_count == 2`
  - `invalid_routes` contains `10.200.0.0/16` and `10.200.1.0/24`
  - `routes_by_prefix_length` contains all 4 routes (Active + Invalid, sorted)
  - `findings["blackhole_routes"] == []` — Invalid routes are excluded from active findings

#### T-AUD-10 — Blackhole route detected in findings (fx-10)

- **Fixture:** fx-10-blackhole-none-hop.json
- **Expected:**
  - `len(findings["blackhole_routes"]) == 1`
  - `findings["blackhole_routes"][0]["prefix"] == "10.30.0.0/16"`
  - `findings["nva_routes"] == []`
  - `findings["bgp_routes"] == []`
  - `findings["default_route_present"] == True`, `default_route_source == "Default"`

#### T-AUD-12 — Production hub-spoke: NVA and BGP routes detected (fx-12)

- **Fixture:** fx-12-hub-spoke-production.json
- **Expected:**
  - `len(findings["nva_routes"]) == 1` — User `0.0.0.0/0` VirtualAppliance
  - `len(findings["bgp_routes"]) == 2` — VGW `192.168.0.0/16` and `192.168.10.0/24`
  - `findings["default_route_present"] == True`, `default_route_source == "User"`
  - `findings["blackhole_routes"] == []`

#### T-AUD-14 — BGP tie visible in audit: all three VGW routes appear in bgp_routes (fx-14)

- **Fixture:** fx-14-bgp-tie-same-prefix.json
- **Expected:**
  - `len(findings["bgp_routes"]) == 3` — two `10.50.0.0/24` + one `10.50.0.0/16`
  - Audit mode does not declare TIED_BGP — it lists all routes as found; BGP tie is only resolved in single-target mode

---

## 6. Unit Tests — `route_preprocessor.py`

#### T-PP-01 through T-PP-15 — All fixtures parse cleanly

For each of the 15 fixtures: call `preprocess(fixture_path)`, assert:
- Result does NOT contain `"error"` key
- `result["route_count"] > 0`
- `result["routes"]` is a non-empty list
- Each route has `"prefix"`, `"prefix_length"`, `"next_hop_type"`, `"source"`, `"state"` keys
- `result["parse_warnings"]` is a list (may be empty)

#### T-PP-11a — Multi-prefix expansion: two-prefix entry expands to two RouteObjects (fx-11)

- **Fixture:** fx-11-multi-prefix-entry.json
- Raw fixture has one entry with `addressPrefix: ["172.20.0.0/16", "172.20.5.0/24"]`
- **Expected:** two `RouteObject`s with `prefix="172.20.0.0/16"` and `prefix="172.20.5.0/24"` respectively, both with identical `next_hop_type`, `source`, `state`

#### T-PP-11b — Multi-prefix expansion: three-prefix entry expands to three RouteObjects (fx-11)

- Raw fixture has one entry with `addressPrefix: ["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"]`
- **Expected:** three separate RouteObjects, all with same `source`, `next_hop_type`, `state`
- Total normalised route count from fx-11: 7 (4 raw entries → 7 expanded objects)

#### T-PP-ERR-01 — File not found returns error dict

- **Input:** non-existent path `/tmp/does_not_exist.json`
- **Expected:** `result["error"]` key present; `"routes"` key absent

#### T-PP-ERR-02 — Invalid JSON returns error dict

- **Input:** temp file containing `"not valid json {{{"`
- **Expected:** `result["error"]` key present

#### T-PP-ERR-03 — Valid JSON but no recognisable routes returns error dict

- **Input:** temp file containing `{"unrelated": "structure"}`
- **Expected:** `result["error"]` key present; `"routes"` key absent

#### T-PP-STATE — Absent/null state field normalised to "Unknown"

- **Input:** route entry with `state` field missing or null
- **Expected:** normalised RouteObject has `state == "Unknown"` (not Python None, not empty string)

---

## 7. Unit Tests — `providers.py`

All subprocess calls mocked via `unittest.mock.patch("subprocess.run")`.

### 7.1 `is_throttle()` — pattern matching

| Test ID | Input | Expected |
|---------|-------|----------|
| T-THROT-01 | `"Throttling: request limit"` | `True` |
| T-THROT-02 | `"Too Many Requests"` | `True` |
| T-THROT-03 | `"rate limit exceeded"` | `True` |
| T-THROT-04 | `"HTTP 429"` | `True` |
| T-THROT-05 | `"AuthorizationFailed"` | `False` |
| T-THROT-06 | `"ResourceNotFound"` | `False` |
| T-THROT-07 | `""` | `False` |
| T-THROT-08 | `"THROTTLING"` (uppercase) | `True` — case-insensitive |

### 7.2 `LocalShell.run()`

#### T-LS-01 — Success: returns stdout string

- Mock `subprocess.run` returns `CompletedProcess(returncode=0, stdout="output text", stderr="")`
- **Expected:** `run(["az", "vm", "show"])` returns `"output text"`

#### T-LS-02 — Non-zero exit: raises ProviderError with stderr content

- Mock returns `CompletedProcess(returncode=1, stdout="", stderr="VM not found")`
- **Expected:** `ProviderError` raised; `str(e)` contains `"VM not found"`

#### T-LS-03 — az CLI not installed: raises ProviderError with install message

- Mock `subprocess.run` raises `FileNotFoundError`
- **Expected:** `ProviderError` raised; message contains `"az CLI not found"`

#### T-LS-04 — az CLI timeout: raises ProviderError with timeout message

- Mock raises `subprocess.TimeoutExpired(cmd="az", timeout=60)`
- **Expected:** `ProviderError` raised; message contains `"timed out after 60s"`

#### T-LS-05 — shell=True is never used (injection safety)

- Capture the call args to `subprocess.run`
- **Expected:** `kwargs` does not contain `shell=True`; first argument is a list, not a string

### 7.3 `AzureRouteProvider.get_nic_name()`

#### T-NIC-01 — Success: NIC name extracted from resource ID last segment

- Mock stdout: `/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/my-nic-name\n`
- **Expected:** returns `"my-nic-name"`

#### T-NIC-02 — Empty stdout: raises VMNotFoundError

- Mock stdout: `""`
- **Expected:** `VMNotFoundError` raised; message contains `vm_name` and `resource_group`

#### T-NIC-03 — Literal "None" stdout: raises VMNotFoundError

- Mock stdout: `"None\n"` (az CLI returns literal string "None" for null JMESPath result)
- **Expected:** `VMNotFoundError` raised

#### T-NIC-04 — RBAC failure: raises RBACError

- Mock `subprocess.run` returns non-zero with stderr containing `"AuthorizationFailed"`
- **Expected:** `RBACError` raised; message references `effectiveRouteTable/action`

#### T-NIC-05 — ResourceNotFound with context="get_nic_name": raises VMNotFoundError (not NICResolutionError)

- Mock returns non-zero with stderr `"ResourceNotFound: VM myvm not found"`
- **Expected:** `VMNotFoundError` raised — NOT `NICResolutionError`

#### T-NIC-06 — Subscription ID appended when provided

- Instantiate `AzureRouteProvider(subscription_id="my-sub-id")`
- Capture args passed to `subprocess.run`
- **Expected:** args vector contains `"--subscription"` followed by `"my-sub-id"`

#### T-NIC-07 — Correct JMESPath query in args vector

- Capture args to `subprocess.run`
- **Expected:** args contains `"--query"` followed by `"networkProfile.networkInterfaces[?primary].id | [0]"`
- This verifies primary NIC selection by flag, not by array position

### 7.4 `AzureRouteProvider.get_effective_routes()`

#### T-ROUTES-01 — Success: raw dict returned unparsed

- Mock stdout: `json.dumps({"value": [...routes...]})` (valid JSON)
- **Expected:** returns a `dict`; does not unwrap or normalize — passes raw structure to preprocessor

#### T-ROUTES-02 — ResourceNotFound with context="get_effective_routes": raises NICResolutionError

- Mock returns non-zero with stderr `"ResourceNotFound: NIC not found"`
- **Expected:** `NICResolutionError` raised — NOT `VMNotFoundError`

⚠️ This is a relational test. `VMNotFoundError` and `NICResolutionError` are both `ProviderError` subclasses triggered by the same stderr pattern — only the caller `context` distinguishes them. If `_classify_error` ignores context, both callers raise `VMNotFoundError`, which misreports the failure layer.

#### T-ROUTES-03 — Non-JSON response: raises ProviderError

- Mock stdout: `"<html>service unavailable</html>"`
- **Expected:** `ProviderError` raised; message contains `"non-JSON"`

#### T-ROUTES-04 — Correct az command vector

- Capture args to `subprocess.run`
- **Expected:** args is `["az", "network", "nic", "show-effective-route-table", "--name", nic_name, "--resource-group", rg, "--output", "json"]`
- Verifies no string interpolation, no `shell=True`, correct subcommand structure

### 7.5 `_call_with_retry()` — retry policy

#### T-RETRY-01 — Throttle on first attempt, success on second: one retry, result returned

- First call raises `ProviderError("Throttling")`, second succeeds
- **Expected:** returns stdout from second call; `time.sleep` called once with value ≤ 30

#### T-RETRY-02 — Throttle on all 4 attempts: ThrottleExhausted raised

- All 4 calls raise `ProviderError("Throttling")`
- **Expected:** `ThrottleExhausted` raised with `attempts=4`; `time.sleep` called 3 times

#### T-RETRY-03 — Throttle on 3 attempts, success on 4th: returns result

- First 3 calls raise `ProviderError("Throttling")`, 4th succeeds
- **Expected:** result returned; `time.sleep` called 3 times

#### T-RETRY-04 — Non-throttle error on first attempt: raises immediately, no retry

- First call raises `ProviderError("AuthorizationFailed")`
- **Expected:** exception propagates immediately; `time.sleep` never called

#### T-RETRY-05 — Backoff formula: sleep durations are 2s, 4s, 8s

- Mock all 4 attempts as throttle
- Capture `time.sleep` call arguments
- **Expected:** sleep called with `[2, 4, 8]` in order (formula: `min(2 ** (attempt + 1), 30)` for attempts 0, 1, 2)

#### T-RETRY-06 — Context string forwarded to _classify_error

- Non-throttle error triggers `_classify_error`
- **Expected:** `_classify_error` receives `context="get_nic_name"` when called from `get_nic_name`; `context="get_effective_routes"` when called from `get_effective_routes`

### 7.6 `_classify_error()` — context-aware routing

| Test ID | stderr pattern | context | Expected exception |
|---------|---------------|---------|-------------------|
| T-CLS-01 | `"AuthorizationFailed"` | `"get_nic_name"` | `RBACError` |
| T-CLS-02 | `"authorization_failed"` | `"get_effective_routes"` | `RBACError` (case-insensitive) |
| T-CLS-03 | `"ResourceNotFound"` | `"get_nic_name"` | `VMNotFoundError` |
| T-CLS-04 | `"resource not found"` | `"get_effective_routes"` | `NICResolutionError` |
| T-CLS-05 | Unknown pattern `"InternalError"` | any | No raise — returns; caller re-raises `ProviderError` |
| T-CLS-06 | `"Throttling"` | any | No raise — handled upstream by `_call_with_retry` |

---

## 8. Unit Tests — `effective_route_inspector.py`

### 8.1 `_enforce_session_prefix()`

| Test ID | Input | Expected output |
|---------|-------|----------------|
| T-SID-01 | `"rt_20260413_120000"` | `"rt_20260413_120000"` (unchanged) |
| T-SID-02 | `"myid"` | `"rt_myid"` |
| T-SID-03 | `"rt_"` | `"rt_"` (already prefixed, unchanged) |
| T-SID-04 | `""` | `"rt_"` |

### 8.2 `_generate_session_id()`

- **Expected:** returned string matches regex `^rt_\d{8}_\d{6}$`
- **Expected:** two calls within the same second return the same value (collision is documented, not prevented)

### 8.3 `_ensure_audit_dir()`

- **T-DIR-01:** non-existent directory → created; returns `Path` object pointing to it
- **T-DIR-02:** existing directory → silently succeeds (`exist_ok=True` semantics)
- **T-DIR-03:** unwritable parent → `SystemExit(2)` raised; stderr message contains path and reason

### 8.4 CLI argument validation

| Test ID | Command | Expected |
|---------|---------|----------|
| T-CLI-01 | `--resource-group rg` (missing `--vm-name`) | Exit 2, argparse usage message |
| T-CLI-02 | `--vm-name vm` (missing `--resource-group`) | Exit 2 |
| T-CLI-03 | `--vm-name vm --resource-group rg --dst-ip not-an-ip` | Exit 2; stderr `"Invalid destination IP: not-an-ip"` |
| T-CLI-04 | `--vm-name vm --resource-group rg --dst-ip 10.0.0.1` | Proceeds to Stage 2; no Stage 1 error |
| T-CLI-05 | `--dst-ip 0.0.0.0` | Valid IPv4 — Stage 1 passes (0.0.0.0 is a valid IP, not a prefix) |
| T-CLI-06 | `--dst-ip 10.0.0.1/24` | Exit 2 — CIDR notation is not a valid `ip_address` |

### 8.5 `_render_table()`

#### T-RENDER-01 — Single-target WINNER format

- **Input:** valid `SingleTargetVerdict` with `result="WINNER"`, `winning_route` populated
- **Expected:** output string contains `VM:`, `NIC:`, `Destination:`, `Result:`, `Winner:`, `Reason:`

#### T-RENDER-02 — Single-target TIED_BGP format

- **Input:** verdict with `result="TIED_BGP"`, `tied_routes` populated
- **Expected:** output shows tied routes; does not show "Winner:" with a single route

#### T-RENDER-03 — Single-target NO_ROUTE format

- **Input:** verdict with `result="NO_ROUTE"`
- **Expected:** output contains `"No active route matches destination"`

#### T-RENDER-04 — Audit format

- **Input:** valid `AuditVerdict` with `mode="audit"`
- **Expected:** output contains `Mode: audit`, route table rows, `Findings:` section

#### T-RENDER-05 — Missing optional field defaults to "n/a"

- **Input:** verdict with `next_hop_ip=None`
- **Expected:** `_render_table` does not raise; renders `"n/a"` for that field

---

## 9. Pipeline Integration Tests — `MockRouteProvider`

`MockRouteProvider` implements `RouteProvider`: `get_nic_name()` returns a hardcoded NIC name; `get_effective_routes()` returns the parsed contents of a fixture file. Injected via `_run_pipeline(args, provider=mock_provider)`. Tests run with a `tmp_path` audit directory.

### 9.1 Artifact lifecycle

#### T-INT-ART-01 — Successful single-target run writes both artifacts

- **Fixture:** fx-01, `dst_ip="10.0.1.50"`
- **Expected:**
  - `{tmp_path}/{session_id}_raw.json` exists and is valid JSON
  - `{tmp_path}/{session_id}_verdict.json` exists and is valid JSON
  - Exit code: 0

#### T-INT-ART-02 — Provider failure: no artifacts written

- `MockRouteProvider.get_nic_name()` raises `VMNotFoundError`
- **Expected:**
  - No `_raw.json` file in `tmp_path`
  - No `_verdict.json` file in `tmp_path`
  - Exit code: 2
  - Stderr contains VM name and resource group

#### T-INT-ART-03 — Preprocessor failure after successful collect: raw written, verdict absent

- `MockRouteProvider.get_effective_routes()` returns `{}` (empty dict — no routes parseable)
- **Expected:**
  - `_raw.json` IS written (Stage 2 succeeded)
  - `_verdict.json` is NOT written (Stage 3 failed)
  - Exit code: 2

This is a pipeline stage isolation test: Stage 2 and Stage 3 artifacts have independent lifecycles.

#### T-INT-ART-04 — Verdict artifact content matches verdict returned to stdout

- Parse `_verdict.json`; parse stdout rendered table
- **Expected:** `verdict["result"]` matches the result shown in stdout; no discrepancy between machine and human output

#### T-INT-ART-05 — Session ID prefix in artifact filenames

- Provide `--session-id=myrun` (no `rt_` prefix)
- **Expected:** artifact files named `rt_myrun_raw.json` and `rt_myrun_verdict.json`

#### T-INT-ART-06 — Audit mode writes AuditVerdict; single-target writes SingleTargetVerdict

- Run audit mode (no `--dst-ip`): verify `verdict["mode"] == "audit"`
- Run single-target mode: verify `verdict["mode"] == "single-target"`

### 9.2 Exit code correctness

| Test ID | Scenario | Expected exit |
|---------|----------|--------------|
| T-INT-EXIT-01 | Successful single-target run | 0 |
| T-INT-EXIT-02 | Successful audit run | 0 |
| T-INT-EXIT-03 | `VMNotFoundError` from provider | 2 |
| T-INT-EXIT-04 | `RBACError` from provider | 2 |
| T-INT-EXIT-05 | `ThrottleExhausted` from provider | 2 |
| T-INT-EXIT-06 | Invalid `--dst-ip` | 2 |
| T-INT-EXIT-07 | Result is `NO_ROUTE` | 0 — this is a valid verdict, not an error |
| T-INT-EXIT-08 | Result is `TIED_BGP` | 0 — tie is a valid verdict, not an error |

Note: Exit code 1 is never emitted. Every non-success is exit 2.

### 9.3 `--nic-name` bypass

#### T-INT-NIC-01 — --nic-name skips get_nic_name call

- Supply `--nic-name my-override-nic`
- **Expected:** `MockRouteProvider.get_nic_name()` is never called; `get_effective_routes("my-override-nic", rg)` is called
- **Expected:** verdict contains `"nic_name": "my-override-nic"`

### 9.4 Relational test: verdict identity fields populated by orchestrator, not lpm_engine

`select_route()` and `audit_routes()` return verdicts without `session_id`, `vm_name`, `resource_group`, `nic_name`. The orchestrator adds them before writing.

#### T-INT-REL-01 — Verdict file contains all four identity fields

- **Expected:** `_verdict.json` contains `session_id`, `vm_name`, `resource_group`, `nic_name`
- **Expected:** `session_id` starts with `"rt_"`
- **Expected:** `vm_name` matches `--vm-name` argument

---

## 10. Ghost Agent Handler Tests

Tests for `_run_effective_route_inspector_handler(tool_call, ghost_cfg)` in `ghost_agent.py`. The subprocess call is mocked — `subprocess.run` patched to return a controlled exit code and write a pre-fabricated verdict file to the audit dir.

#### T-GA-01 — Exit 0: verdict file read and returned as dict

- Subprocess mock: exit code 0; pre-write `{session_id}_verdict.json` to audit dir
- **Expected:** handler returns the verdict dict; `tool_error` key absent

#### T-GA-02 — Exit 2, no verdict file: error dict returned

- Subprocess mock: exit code 2; no file written
- **Expected:** handler returns `{"tool_error": True, "session_id": ..., "error": "...exited with code 2..."}`

#### T-GA-03 — Subprocess args: required params always present

- `tool_call["parameters"]` = `{"vm_name": "myvm", "resource_group": "rg"}`
- Capture subprocess args
- **Expected:** args include `sys.executable`, path to `effective_route_inspector.py`, `--vm-name myvm`, `--resource-group rg`, `--session-id rt_...`, `--audit-dir ...`

#### T-GA-04 — Subprocess args: optional params absent when not in tool_call

- `tool_call["parameters"]` has no `dst_ip`, `nic_name`, `subscription_id`
- **Expected:** args do NOT contain `--dst-ip`, `--nic-name`, `--subscription-id`

#### T-GA-05 — Subprocess args: optional params included when present

- `tool_call["parameters"]` includes `dst_ip="10.0.0.1"`, `nic_name="my-nic"`, `subscription_id="sub-123"`
- **Expected:** args contain `["--dst-ip", "10.0.0.1"]`, `["--nic-name", "my-nic"]`, `["--subscription-id", "sub-123"]`

#### T-GA-06 — Module path uses _ROOT anchor, no ".."

- Capture subprocess args
- **Expected:** path to `effective_route_inspector.py` is constructed via `_ROOT / "effective-route-inspector" / "effective_route_inspector.py"`; string `".."` does not appear in the path

#### T-GA-07 — Session ID generated in handler starts with rt_ prefix

- **Expected:** `--session-id` value in subprocess args matches `^rt_\d{8}_\d{6}$`

#### T-GA-08 — AUDIT_DIR from ghost_cfg, not hardcoded

- Set `ghost_cfg["AUDIT_DIR"] = tmp_path`
- **Expected:** `--audit-dir` in subprocess args equals `str(tmp_path)`

---

## 11. Null Result and Boundary Tests

Tests that explicitly assert on absent data and zero-count results — not gaps in coverage.

| Test ID | Scenario | What is asserted as absent/zero |
|---------|----------|--------------------------------|
| T-NULL-01 | fx-09, dst=203.0.113.1 (no matching route) | `winning_route is None`, `shadowed_candidates == []`, `anomaly_warnings == []` |
| T-NULL-02 | fx-01 audit — no anomalies | `findings["blackhole_routes"] == []`, `findings["nva_routes"] == []`, `findings["bgp_routes"] == []` |
| T-NULL-03 | fx-14, dst=10.50.0.100 (TIED_BGP) | `winning_route is None` — no default selection |
| T-NULL-04 | fx-07, dst=8.8.8.8 (unrelated invalid routes) | `anomaly_warnings == []` — false positive guard |
| T-NULL-05 | fx-06, dst=10.100.5.30 (None-hop in shadowed route) | `anomaly_warnings == []` — BLACKHOLE not triggered by non-winning route |
| T-NULL-06 | Preprocessor: file not found | `result` has `"error"` key; `"routes"` key is absent |
| T-NULL-07 | Provider failure before Stage 2 write | `_raw.json` does not exist in audit dir |

---

## 12. Accuracy Checklist

One entry per fixture, both modes where both are exercised. Check off before marking implementation complete.

### Single-target mode

- [ ] **fx-01** `dst=10.0.1.50`: winner=`10.0.1.0/24` VnetLocal, reason=LPM_ONLY, no warnings
- [ ] **fx-01** `dst=10.0.3.200`: winner=`10.0.3.0/24` VnetLocal, reason=LPM_ONLY
- [ ] **fx-02** `dst=172.16.10.20`: winner=`172.16.10.0/24` User VirtualAppliance, reason=SOURCE_PRECEDENCE, NVA_WARNING
- [ ] **fx-03** `dst=10.2.5.10`: winner=`10.2.0.0/16` Default VnetPeering, reason=LPM_ONLY, **no NVA warning** (UDR is shadowed)
- [ ] **fx-04** `dst=192.168.5.10`: winner=`192.168.0.0/16` User VirtualAppliance, NVA_WARNING
- [ ] **fx-05** `dst=8.8.8.8`: winner=`0.0.0.0/0`, is_zero_route=True
- [ ] **fx-05** `dst=10.0.1.50`: winner=`10.0.1.0/24`, shadowed=`0.0.0.0/0`
- [ ] **fx-06** `dst=10.100.5.30`: winner=`10.100.0.0/16` VGW, reason=SOURCE_PRECEDENCE, **no BLACKHOLE warning** (None-hop Default is shadowed), shadowed includes `0.0.0.0/0`
- [ ] **fx-06** `dst=10.100.50.10`: winner=`10.100.50.0/24` VGW, reason=LPM_ONLY, shadowed includes both /16 routes and `0.0.0.0/0`
- [ ] **fx-07** `dst=10.200.1.50`: winner=`0.0.0.0/0`, INVALID_SHADOW for both `10.200.1.0/24` and `10.200.0.0/16`
- [ ] **fx-07** `dst=8.8.8.8`: winner=`0.0.0.0/0`, **no INVALID_SHADOW** (invalid routes don't cover 8.8.8.8)
- [ ] **fx-08** `dst=10.5.10.100`: winner=`10.5.10.100/32`, prefix_length=32, NVA_WARNING
- [ ] **fx-09** `dst=203.0.113.1`: result=NO_ROUTE, **no fabricated winner**
- [ ] **fx-10** `dst=10.30.0.50`: winner=`10.30.0.0/16` nextHopType="None", BLACKHOLE_WARNING
- [ ] **fx-11** `dst=172.20.5.10`: winner=`172.20.5.0/24` (expanded from multi-prefix entry)
- [ ] **fx-12** `dst=192.168.10.50`: winner=`192.168.10.0/24` VGW, reason=LPM_ONLY
- [ ] **fx-12** `dst=8.8.8.8`: winner=`0.0.0.0/0` User VirtualAppliance, NVA_WARNING
- [ ] **fx-12** `dst=192.168.5.30`: winner=`192.168.0.0/16` VGW, reason=LPM_ONLY
- [ ] **fx-13** `dst=10.3.5.20`: winner=`10.3.0.0/16`, INVALID_SHADOW for `10.3.5.0/24` only
- [ ] **fx-13** `dst=10.4.5.20`: winner=`0.0.0.0/0`, INVALID_SHADOW for `10.4.0.0/16` only (not `10.3.5.0/24`)
- [ ] **fx-14** `dst=10.50.0.100`: result=TIED_BGP, tied_routes has 2 routes, **no winner selected**
- [ ] **fx-14** `dst=10.50.5.10`: result=WINNER, winner=`10.50.0.0/16` VGW, reason=LPM_ONLY, shadowed=`[0.0.0.0/0]` (the two /24 routes do not cover this destination)
- [ ] **fx-15** `dst=10.0.1.130`: winner=`10.0.1.128/28` VnetLocal, **no NVA warning** (/28 overrides to VnetLocal)
- [ ] **fx-15** `dst=10.0.1.50`: winner=`10.0.1.0/24` User VirtualAppliance, NVA_WARNING

### Audit mode

- [ ] **fx-01**: 5 active, 0 invalid, no findings
- [ ] **fx-07**: 2 active, 2 invalid; invalid_routes lists both 10.200.x routes
- [ ] **fx-10**: blackhole_routes=`[10.30.0.0/16]`; nva_routes=[], bgp_routes=[]
- [ ] **fx-12**: nva_routes=`[0.0.0.0/0]`; bgp_routes=`[192.168.0.0/16, 192.168.10.0/24]`; default_route_present=True, source=User
- [ ] **fx-14**: bgp_routes has 3 entries (two /24 + one /16)
- [ ] **fx-13**: 5 active, 2 invalid; invalid_routes=`[10.3.5.0/24, 10.4.0.0/16]`

---

## 13. Known Unknowns (Verify During Implementation)

These assumptions in the design are flagged as unverified. Relevant test cases must be updated once empirically confirmed.

| # | Unknown | Affected tests | Verification method |
|---|---------|---------------|---------------------|
| U1 | Throttle error string patterns in az CLI stderr | T-RETRY-01 through T-RETRY-06, T-THROT-01 through T-THROT-08 | Run against Azure API, deliberately exhaust quota; capture raw stderr |
| U2 | `az network nic show-effective-route-table -o json` envelope key (`"value"` vs `"effectiveRoutes"`) | T-PP-01 through T-PP-15 | Inspect a live fixture capture; preprocessor handles both but document which is observed |
| U3 | `primary` boolean present on single-NIC VMs | T-NIC-07, T-INT-NIC-01 | Run `az vm show` against a single-NIC VM; inspect `networkProfile.networkInterfaces[0]` |
| U4 | Mixed IPv4/IPv6 route table behavior with IPv4 dst_ip | No current test | Add fixture with mixed prefixes; test that `ip_network()` parse failure is a `parse_warning`, not a crash |
