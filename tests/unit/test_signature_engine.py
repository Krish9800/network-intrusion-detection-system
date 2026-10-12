"""Unit tests for Snort-style signature matching engine."""

from nids.engine.signature_engine import SignatureEngine
from nids.models.enums import AlertSeverity, AnomalyType, PacketProtocol
from nids.models.schemas import DecodedPacket, NIDSRule


def test_signature_content_matching() -> None:
    """Verify exact and case-insensitive payload content matching."""
    rule = NIDSRule(
        sid=2001,
        name="ET MALWARE Webshell cmd.jsp access",
        protocol=PacketProtocol.TCP,
        dst_port="8080",
        content="cmd.jsp",
        nocase=True,
        severity=AlertSeverity.HIGH,
        mitre_attack_id="T1059",
    )
    engine = SignatureEngine([rule])

    # Matching packet
    pkt_match = DecodedPacket(
        raw_length=120,
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.10",
        src_port=49000,
        dst_port=8080,
        payload_bytes=b"GET /uploads/CMD.JSP?cmd=whoami HTTP/1.1\r\n\r\n",
    )
    alerts = engine.match_packet(pkt_match)
    assert len(alerts) == 1
    assert alerts[0].sid == 2001
    assert alerts[0].anomaly_type == AnomalyType.SIGNATURE_MATCH
    assert alerts[0].mitre_attack_id == "T1059"
    assert "CMD.JSP" in str(alerts[0].payload_snippet)

    # Non-matching packet (different port)
    pkt_diff_port = DecodedPacket(
        raw_length=120,
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.10",
        src_port=49000,
        dst_port=80,  # rule requires 8080
        payload_bytes=b"GET /uploads/CMD.JSP HTTP/1.1\r\n\r\n",
    )
    assert len(engine.match_packet(pkt_diff_port)) == 0


def test_signature_regex_matching() -> None:
    """Verify regex pattern matching on application payload."""
    rule = NIDSRule(
        sid=2002,
        name="Suspicious Encoded PowerShell in Payload",
        protocol=PacketProtocol.TCP,
        regex=r"(?i)powershell(\.exe)?\s+-[eE](nc)?",
        severity=AlertSeverity.CRITICAL,
    )
    engine = SignatureEngine([rule])

    pkt = DecodedPacket(
        raw_length=150,
        protocol=PacketProtocol.TCP,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.99",
        src_port=12345,
        dst_port=4444,
        payload_bytes=b"powershell -enc SQBFAFgA...",
    )
    alerts = engine.match_packet(pkt)
    assert len(alerts) == 1
    assert alerts[0].sid == 2002
    assert alerts[0].severity == AlertSeverity.CRITICAL


def test_port_ranges_and_disabled_rules() -> None:
    """Verify port ranges (e.g. 1024:65535) and disabled rule skipping."""
    rule_disabled = NIDSRule(
        sid=9999,
        name="Disabled Rule",
        protocol=PacketProtocol.TCP,
        enabled=False,
    )
    rule_range = NIDSRule(
        sid=3001,
        name="High Ephemeral Port Access",
        protocol=PacketProtocol.TCP,
        dst_port="1024:5000",
    )
    engine = SignatureEngine([rule_disabled, rule_range])
    assert len(engine.rules) == 1  # disabled filtered out

    # Port in range
    pkt_in = DecodedPacket(
        raw_length=60,
        protocol=PacketProtocol.TCP,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=100,
        dst_port=3000,
    )
    assert len(engine.match_packet(pkt_in)) == 1

    # Port outside range
    pkt_out = DecodedPacket(
        raw_length=60,
        protocol=PacketProtocol.TCP,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=100,
        dst_port=6000,
    )
    assert len(engine.match_packet(pkt_out)) == 0
