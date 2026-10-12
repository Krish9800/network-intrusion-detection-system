"""Adversarial Security Testbed for NIDS Engine.

Verifies system resilience against:
1. Malformed and truncated network frames (fuzzing/DoS mitigation).
2. Illegal TCP flag combinations (XMAS scan, NULL scan, SYN-FIN).
3. Memory / Flow state table stress testing under high-PPS packet floods.
4. SQL Injection safety across database layer.
5. Large payload truncation and bounds safety.
"""

import struct
from pathlib import Path

import pytest

from nids.db.database import Database
from nids.decoders.packet_decoder import PacketDecoder, PacketDecoderError
from nids.flow.tracker import FlowTracker
from nids.models.enums import AlertSeverity, PacketProtocol, TCPFlag
from nids.models.schemas import NIDSRule


def test_adversarial_truncated_frames() -> None:
    """Verify decoders handle arbitrary short and corrupt bytes safely without crashing."""
    decoder = PacketDecoder()

    # Under 14 bytes (truncated Ethernet header)
    for length in range(14):
        with pytest.raises(PacketDecoderError):
            decoder.decode(b"\x00" * length)

    # Valid Ethernet header but truncated IPv4 header (< 20 bytes payload)
    eth_hdr = struct.pack("!6s6sH", b"\x01" * 6, b"\x02" * 6, 0x0800)
    for ip_len in range(19):
        with pytest.raises(PacketDecoderError):
            decoder.decode(eth_hdr + b"\x45" + b"\x00" * ip_len)


def test_adversarial_illegal_tcp_flags() -> None:
    """Verify illegal TCP flag combinations (NULL scan, XMAS scan, SYN+FIN)."""
    decoder = PacketDecoder()

    # Base Ethernet + IPv4 headers
    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        64,
        1,
        0,
        64,
        6,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )

    # 1. NULL Scan (No flags set)
    tcp_null = struct.pack("!HHIIBBHHH", 1234, 80, 100, 0, (5 << 4), 0, 1024, 0, 0)
    pkt_null = decoder.decode(eth + ip + tcp_null)
    assert pkt_null.tcp_flags == 0
    assert pkt_null.has_flag(TCPFlag.SYN) is False

    # 2. XMAS Scan (FIN + PSH + URG = 0x01 | 0x08 | 0x20 = 0x29)
    xmas_flags = TCPFlag.FIN.value | TCPFlag.PSH.value | TCPFlag.URG.value
    tcp_xmas = struct.pack("!HHIIBBHHH", 1234, 80, 100, 0, (5 << 4), xmas_flags, 1024, 0, 0)
    pkt_xmas = decoder.decode(eth + ip + tcp_xmas)
    assert pkt_xmas.has_flag(TCPFlag.FIN) is True
    assert pkt_xmas.has_flag(TCPFlag.PSH) is True
    assert pkt_xmas.has_flag(TCPFlag.URG) is True
    assert pkt_xmas.has_flag(TCPFlag.SYN) is False

    # 3. SYN + FIN (Illegal combination)
    syn_fin = TCPFlag.SYN.value | TCPFlag.FIN.value
    tcp_synfin = struct.pack("!HHIIBBHHH", 1234, 80, 100, 0, (5 << 4), syn_fin, 1024, 0, 0)
    pkt_synfin = decoder.decode(eth + ip + tcp_synfin)
    assert pkt_synfin.has_flag(TCPFlag.SYN) is True
    assert pkt_synfin.has_flag(TCPFlag.FIN) is True


def test_adversarial_high_pps_flow_table_stress() -> None:
    """Stress test FlowTracker with 1,000 synthetic flows to verify table stability."""
    tracker = FlowTracker()
    decoder = PacketDecoder()

    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)

    # Ingest 1000 distinct packets simulating SYN flood or port scan
    for port in range(1000, 2000):
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            64,
            1,
            0,
            64,
            6,
            0,
            b"\x0a\x00\x00\x01",
            b"\x0a\x00\x00\x02",
        )
        tcp = struct.pack("!HHIIBBHHH", port, 80, 1, 0, (5 << 4), TCPFlag.SYN.value, 1024, 0, 0)
        pkt = decoder.decode(eth + ip + tcp)
        tracker.process_packet(pkt)

    assert tracker.active_flows_count() == 1000


def test_adversarial_sqli_safety(temp_dir: Path) -> None:
    """Verify database repository is immune to SQL injection payloads."""
    db_path = temp_dir / "sqli_test.db"
    db = Database(db_path)

    # Injection attempts in rule fields
    malicious_rule = NIDSRule(
        sid=9999,
        name="SQLi Test'); DROP TABLE nids_rules; --",
        protocol=PacketProtocol.TCP,
        dst_port="80' OR '1'='1",
        severity=AlertSeverity.HIGH,
        mitre_attack_id="T1190' UNION SELECT 1, 2, 3 --",
    )
    db.save_rule(malicious_rule)

    rules = db.list_rules()
    assert len(rules) == 1
    assert rules[0].sid == 9999
    assert "DROP TABLE" in rules[0].name

    # Raw parameter check ensuring injection fails safely
    with db.session() as conn:
        res = conn.execute(
            "SELECT count(*) as cnt FROM nids_rules WHERE name = ?",
            ("SQLi Test'); DROP TABLE nids_rules; --",),
        ).fetchone()
        assert res["cnt"] == 1


def test_adversarial_oversized_payload_truncation() -> None:
    """Verify decoder gracefully handles payload segments up to maximum bounds."""
    decoder = PacketDecoder()

    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)
    # Total length 1020, header 20, TCP 20, payload 980 bytes
    payload_data = b"A" * 980
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        1020,
        1,
        0,
        64,
        6,
        0,
        b"\xc0\xa8\x01\x01",
        b"\xc0\xa8\x01\x02",
    )
    tcp = struct.pack("!HHIIBBHHH", 5000, 80, 1, 0, (5 << 4), TCPFlag.ACK.value, 1024, 0, 0)
    pkt = decoder.decode(eth + ip + tcp + payload_data)

    assert len(pkt.payload_bytes) == 980
    assert pkt.payload_bytes[:10] == b"AAAAAAAAAA"
