# Investigation Report — ghost_20260224_065616
_Generated: 2026-02-24T06:57:12.642089+00:00_
_Confidence: high_

## Root Cause
Traffic to 10.0.1.5/32 is being routed to 10.0.1.100 due to a custom route in the route table associated with the subnet. Audit ID ghost_20260224_065616_004 shows the route in the table, and audit ID ghost_20260224_065616_006 confirms it is the active route.

**Confirmed:** H1

**Refuted:** H2, H3

## Recommended Actions
- Remove or modify the route in the ghost-demo-blackhole-rt route table to allow traffic to 10.0.1.5/32 to reach its destination.
