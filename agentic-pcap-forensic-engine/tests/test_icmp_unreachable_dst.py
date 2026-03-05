"""Tests for ICMP error-type inner-IP extraction (Types 3, 5, and 11).

All ICMP error messages embed the original IP header in their payload,
producing two ip.dst fields per packet. The outer dst is the notification
recipient (original sender). The inner dst is the actual destination the
original packet was trying to reach — the critical diagnostic value.

Packet structures:

  Type 3 — Destination Unreachable:
    Outer IP: src=router,    dst=original_sender  (notification recipient)
    Inner IP: src=original_sender, dst=unreachable_host

  Type 5 — Redirect:
    Outer IP: src=router,    dst=host_being_redirected  (notification recipient)
    ICMP:     redir_gw = new gateway IP
    Inner IP: src=host_being_redirected, dst=redirect_for  (traffic to redirect)

  Type 11 — TTL Exceeded:
    Outer IP: src=dropping_router, dst=original_sender  (notification recipient)
    Inner IP: src=original_sender,  dst=original_dst  (destination stuck in loop)
"""
from pathlib import Path

from pcap_forensics import extract_icmp, reduce_icmp

SAMPLE_PCAPS = Path(__file__).parent / "sample_pcaps"


# ---------------------------------------------------------------------------
# extract_icmp() — inner IP dst (Types 3, 5, 11)
# ---------------------------------------------------------------------------

class TestExtractIcmpType3InnerDst:
    """extract_icmp() must populate inner_dst_ip on Type 3 packets."""

    def test_host_unreachable_inner_dst(self):
        """icmp_unreachable_host.pcap: inner dst should be 10.0.0.99.

        Outer: src=10.0.0.254 (router), dst=10.0.0.1 (notification recipient)
        Inner: dst=10.0.0.99 (actual unreachable host)
        """
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_unreachable_host.pcap")
        type3 = [p for p in packets if p.get("type") == 3]
        assert type3, "Expected at least one ICMP type 3 packet"
        for pkt in type3:
            assert pkt.get("inner_dst_ip") == "10.0.0.99", (
                f"Frame {pkt['frame']}: inner_dst_ip should be 10.0.0.99, "
                f"got {pkt.get('inner_dst_ip')!r}"
            )
            assert pkt.get("dst_ip") == "10.0.0.1", "outer dst_ip is notification recipient"

    def test_port_unreachable_inner_dst(self):
        """icmp_unreachable_port.pcap: inner dst should be 10.0.0.2 (server)."""
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_unreachable_port.pcap")
        type3 = [p for p in packets if p.get("type") == 3]
        assert type3
        for pkt in type3:
            assert pkt.get("inner_dst_ip") == "10.0.0.2", (
                f"Frame {pkt['frame']}: inner_dst_ip should be 10.0.0.2, "
                f"got {pkt.get('inner_dst_ip')!r}"
            )
            assert pkt.get("code") == 3  # Port Unreachable


class TestExtractIcmpType5Redirect:
    """extract_icmp() must populate inner_dst_ip and redir_gw on Type 5 packets."""

    def test_redirect_inner_dst(self):
        """icmp_redirect.pcap: inner dst (redirect_for) should be 192.168.1.50.

        Outer: src=10.0.0.254 (router), dst=10.0.0.1 (host being redirected)
        icmp.redir_gw: 10.0.0.253 (new gateway)
        Inner: dst=192.168.1.50 (destination traffic should be redirected for)
        """
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_redirect.pcap")
        type5 = [p for p in packets if p.get("type") == 5]
        assert type5, "Expected at least one ICMP type 5 packet"
        for pkt in type5:
            assert pkt.get("inner_dst_ip") == "192.168.1.50", (
                f"Frame {pkt['frame']}: inner_dst_ip should be 192.168.1.50, "
                f"got {pkt.get('inner_dst_ip')!r}"
            )
            assert pkt.get("dst_ip") == "10.0.0.1", "outer dst_ip is host being redirected"

    def test_redirect_redir_gw(self):
        """icmp_redirect.pcap: redir_gw should be 10.0.0.253 (the new gateway)."""
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_redirect.pcap")
        type5 = [p for p in packets if p.get("type") == 5]
        assert type5
        for pkt in type5:
            assert pkt.get("redir_gw") == "10.0.0.253", (
                f"Frame {pkt['frame']}: redir_gw should be 10.0.0.253, "
                f"got {pkt.get('redir_gw')!r}"
            )

    def test_non_redirect_packets_have_empty_redir_gw(self):
        """Echo request packets in the redirect pcap must have redir_gw=''."""
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_redirect.pcap")
        non_type5 = [p for p in packets if p.get("type") != 5]
        assert non_type5, "Expected non-redirect packets (echo requests) in pcap"
        for pkt in non_type5:
            assert pkt.get("redir_gw") == "", (
                f"Frame {pkt['frame']} (type={pkt.get('type')}): "
                f"redir_gw should be empty, got {pkt.get('redir_gw')!r}"
            )

    def test_non_redirect_packets_have_no_inner_dst(self):
        """Echo request packets must NOT have inner_dst_ip."""
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_redirect.pcap")
        non_type5 = [p for p in packets if p.get("type") != 5]
        for pkt in non_type5:
            assert "inner_dst_ip" not in pkt, (
                f"Frame {pkt['frame']} (type={pkt.get('type')}): "
                "inner_dst_ip must not be set on non-error packets"
            )


class TestExtractIcmpType11TtlExceeded:
    """extract_icmp() must populate inner_dst_ip on Type 11 packets."""

    def test_ttl_exceeded_inner_dst(self):
        """icmp_ttl_exceeded.pcap: inner dst should be 192.168.99.1 (the target).

        Outer: src=172.16.0.1 (dropping router), dst=10.0.0.1 (original sender)
        Inner: dst=192.168.99.1 (destination the packet was trying to reach)
        """
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_ttl_exceeded.pcap")
        type11 = [p for p in packets if p.get("type") == 11]
        assert type11, "Expected at least one ICMP type 11 packet"
        for pkt in type11:
            assert pkt.get("inner_dst_ip") == "192.168.99.1", (
                f"Frame {pkt['frame']}: inner_dst_ip should be 192.168.99.1, "
                f"got {pkt.get('inner_dst_ip')!r}"
            )
            assert pkt.get("src_ip") == "172.16.0.1", "src_ip is the dropping router"
            assert pkt.get("dst_ip") == "10.0.0.1", "dst_ip is notification recipient"

    def test_non_ttl_exceeded_packets_have_no_inner_dst(self):
        """Echo request packets in the TTL pcap must NOT have inner_dst_ip."""
        packets = extract_icmp(SAMPLE_PCAPS / "icmp_ttl_exceeded.pcap")
        non_type11 = [p for p in packets if p.get("type") != 11]
        assert non_type11, "Expected non-TTL-exceeded packets in pcap"
        for pkt in non_type11:
            assert "inner_dst_ip" not in pkt, (
                f"Frame {pkt['frame']} (type={pkt.get('type')}): "
                "inner_dst_ip must not be set on non-error packets"
            )


# ---------------------------------------------------------------------------
# reduce_icmp() — Semantic JSON output (Types 3, 5, 11)
# ---------------------------------------------------------------------------

class TestReduceIcmpUnreachableDst:
    """reduce_icmp() must surface unreachable_dst in unreachable_details."""

    def test_host_unreachable_details_include_unreachable_dst(self):
        """unreachable_details must contain unreachable_dst=10.0.0.99."""
        raw = extract_icmp(SAMPLE_PCAPS / "icmp_unreachable_host.pcap")
        result = reduce_icmp(raw)

        assert "unreachable_details" in result
        entry = result["unreachable_details"][0]
        assert entry["src"] == "10.0.0.254", "src is the router"
        assert entry["dst"] == "10.0.0.1", "dst is the notification recipient"
        assert entry.get("unreachable_dst") == "10.0.0.99", (
            f"unreachable_dst should be 10.0.0.99, got {entry.get('unreachable_dst')!r}"
        )
        assert entry["code"] == 1   # Host Unreachable
        assert entry["count"] >= 1

    def test_port_unreachable_details_include_unreachable_dst(self):
        """unreachable_details must contain unreachable_dst=10.0.0.2."""
        raw = extract_icmp(SAMPLE_PCAPS / "icmp_unreachable_port.pcap")
        result = reduce_icmp(raw)

        entry = result["unreachable_details"][0]
        assert entry.get("unreachable_dst") == "10.0.0.2"
        assert entry["code"] == 3   # Port Unreachable


class TestReduceIcmpRedirect:
    """reduce_icmp() must surface gateway and redirect_for in redirect_details."""

    def test_redirect_details_structure(self):
        """redirect_details must have correct src, dst, gateway, redirect_for."""
        raw = extract_icmp(SAMPLE_PCAPS / "icmp_redirect.pcap")
        result = reduce_icmp(raw)

        assert "redirect_details" in result, "Expected redirect_details in output"
        assert len(result["redirect_details"]) >= 1

        entry = result["redirect_details"][0]
        assert entry["src"] == "10.0.0.254", "src is the router sending redirect"
        assert entry["dst"] == "10.0.0.1", "dst is the host being redirected"
        assert entry.get("gateway") == "10.0.0.253", (
            f"gateway should be 10.0.0.253 (the new gateway from ICMP header), "
            f"got {entry.get('gateway')!r}"
        )
        assert entry.get("redirect_for") == "192.168.1.50", (
            f"redirect_for should be 192.168.1.50 (inner IP dst), "
            f"got {entry.get('redirect_for')!r}"
        )
        assert entry["count"] >= 1

    def test_redirect_gateway_is_not_notification_recipient(self):
        """gateway must not equal dst (the old bug: dst was used as gateway)."""
        raw = extract_icmp(SAMPLE_PCAPS / "icmp_redirect.pcap")
        result = reduce_icmp(raw)

        for entry in result["redirect_details"]:
            assert entry.get("gateway") != entry.get("dst"), (
                "gateway must be the new forwarding router, not the "
                "notification recipient — these are different hosts"
            )


class TestReduceIcmpTtlExceeded:
    """reduce_icmp() must surface original_dst and dst in ttl_exceeded_sources."""

    def test_ttl_exceeded_sources_structure(self):
        """ttl_exceeded_sources must have correct src, dst, original_dst."""
        raw = extract_icmp(SAMPLE_PCAPS / "icmp_ttl_exceeded.pcap")
        result = reduce_icmp(raw)

        assert "ttl_exceeded_sources" in result, "Expected ttl_exceeded_sources in output"
        assert len(result["ttl_exceeded_sources"]) >= 1

        entry = result["ttl_exceeded_sources"][0]
        assert entry["src"] == "172.16.0.1", "src is the router that dropped the packet"
        assert entry["dst"] == "10.0.0.1", "dst is the notification recipient"
        assert entry.get("original_dst") == "192.168.99.1", (
            f"original_dst should be 192.168.99.1 (destination stuck in loop), "
            f"got {entry.get('original_dst')!r}"
        )
        assert entry["count"] >= 1

    def test_ttl_exceeded_groups_by_src_and_original_dst(self):
        """Same (src, original_dst) pair must be collapsed into one entry."""
        raw = extract_icmp(SAMPLE_PCAPS / "icmp_ttl_exceeded.pcap")
        result = reduce_icmp(raw)

        # All type-11 packets share the same src (172.16.0.1) and original_dst
        # (192.168.99.1) — they should collapse to exactly one group.
        assert len(result["ttl_exceeded_sources"]) == 1, (
            "All TTL-exceeded packets with the same (src, original_dst) "
            "should be grouped into a single entry"
        )
        assert result["ttl_exceeded_sources"][0]["count"] == 10
