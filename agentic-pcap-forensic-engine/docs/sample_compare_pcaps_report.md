## Executive Summary

The network health has slightly degraded, with the introduction of a potential ARP spoofing issue. Specifically, IP address 10.0.0.5 is now associated with two different MAC addresses (aa:bb:cc:dd:ee:05 and ff:ee:dd:cc:bb:aa) in Capture B, which was not the case in Capture A. All other metrics remain stable.

## Change Summary Table

| Protocol | Metric                      | Capture A | Capture B | Delta | Assessment |
|----------|-----------------------------|-----------|-----------|-------|------------|
| ARP      | Total Requests              | 5         | 5         | 0     | STABLE     |
| ARP      | Total Replies               | 5         | 15        | +200%  | STABLE    |
| ARP      | Unanswered Requests         | 0         | 0         | 0     | STABLE     |
| ARP      | Gratuitous ARP Count        | 0         | 0         | 0     | STABLE     |
| ARP      | IP-MAC Conflicts            | 0         | 1         | +1    | NEW ISSUE  |
| ICMP     | Echo Pairs Matched          | 10        | 10        | 0     | STABLE     |
| ICMP     | RTT Median (ms)             | 5.0       | 5.0       | 0     | STABLE     |
| TCP      | Streams Total               | 1         | 1         | 0     | STABLE     |
| TCP      | Retransmission Rate         | 0%        | 0%        | 0     | STABLE     |
| TCP      | Handshake Success Rate      | 100%      | 100%      | 0     | STABLE     |
| TCP      | Zero Window Events          | 0         | 0         | 0     | STABLE     |
| TCP      | RST Teardown Rate           | 0%        | 0%        | 0     | STABLE     |
| DNS      | Queries Total               | 10        | 10        | 0     | STABLE     |
| DNS      | Responses Total             | 10        | 10        | 0     | STABLE     |
| DNS      | Unanswered Queries          | 0         | 0         | 0     | STABLE     |
| DNS      | Latency Median (ms)         | 15.0      | 15.0      | 0     | STABLE     |
| DNS      | DNS Servers Queried         | 1         | 1         | 0     | STABLE     |

## New Issues (Capture B only)

| Severity | Protocol | Issue            | Detail                                  | Frame(s) |
|----------|----------|------------------|-----------------------------------------|----------|
| MEDIUM   | ARP      | IP-MAC Conflict  | IP 10.0.0.5 has MACs aa:bb:cc:dd:ee:05 and ff:ee:dd:cc:bb:aa | 63, 68    |

## Resolved Issues (Capture A only)

No issues from Capture A were resolved.

## Regressions

No regressions detected.

## Remediation

1.  **Investigate ARP Spoofing:**
    *   Command: `tcpdump -n -i eth0 arp and host 10.0.0.5` (on a monitoring host)
    *   Purpose: Capture ARP traffic related to 10.0.0.5 to observe the conflicting ARP replies.
    *   Command: Review switch logs for MAC address flapping between ports associated with aa:bb:cc:dd:ee:05 and ff:ee:dd:cc:bb:aa
    *   Purpose: Determine the physical location of the conflicting MAC addresses.
2.  **Mitigation (if necessary):**
    *   Configure ARP inspection or Dynamic ARP Inspection (DAI) on network switches to prevent ARP spoofing. The specific commands depend on the switch vendor (e.g., Cisco, Juniper). Example (Cisco):
        ```
        ip arp inspection vlan <vlan_id>
        ip arp inspection validate src-mac dst-mac ip
        interface <interface_id>
        ip arp inspection limit rate 15
        ```
