"""Unit tests for NIDS domain models, enums, and schemas."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from nids.models.enums import (
    AlertSeverity,
    AnomalyType,
    FlowState,
    PacketProtocol,
    TCPFlag,
)
from nids.models.schemas import (
    DecodedPacket,
    NetworkFlow,
    NIDSAlert,
    NIDSRule,
)


def test_packet_protocol_values() -> None:
    """Verify supported protocol enums."""
    assert PacketProtocol.ETHERNET.value == "ethernet"
    assert PacketProtocol.IPV4.value == "ipv4"
    assert PacketProtocol.IPV6.value == "ipv6"
    assert PacketProtocol.TCP.value == "tcp"
    assert PacketProtocol.UDP.value == "udp"
    assert PacketProtocol.ICMP.value == "icmp"
    assert PacketProtocol.DNS.value == "dns"
    assert PacketProtocol.HTTP.value == "http"


def test_tcp_flags_bitfield() -> None:
    """Verify bitwise operations on TCPFlag."""
    flags = TCPFlag.SYN | TCPFlag.ACK
    assert flags.value == 0x12
    assert bool(flags & TCPFlag.SYN) is True
    assert bool(flags & TCPFlag.ACK) is True
    assert bool(flags & TCPFlag.FIN) is False


def test_flow_state_values() -> None:
    """Verify FlowState lifecycle states."""
    assert FlowState.NEW.value == "new"
    assert FlowState.SYN_SENT.value == "syn_sent"
    assert FlowState.ESTABLISHED.value == "established"
    assert FlowState.CLOSED.value == "closed"


def test_decoded_packet_creation_and_flags() -> None:
    """Verify DecodedPacket model validation and flag helpers."""
    pkt = DecodedPacket(
        raw_length=74,
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=80,
        tcp_flags=TCPFlag.SYN.value,
        payload_bytes=b"GET / HTTP/1.1\r\n",
    )
    assert pkt.packet_id is not None
    assert pkt.protocol == PacketProtocol.TCP
    assert pkt.has_flag(TCPFlag.SYN) is True
    assert pkt.has_flag(TCPFlag.ACK) is False
    assert pkt.raw_length == 74


def test_decoded_packet_frozen() -> None:
    """Verify DecodedPacket immutability."""
    pkt = DecodedPacket(raw_length=60, protocol=PacketProtocol.ICMP)
    with pytest.raises(ValidationError):
        pkt.raw_length = 100


def test_network_flow_metrics() -> None:
    """Verify NetworkFlow packet counters and duration calculations."""
    t0 = datetime.now(UTC)
    flow = NetworkFlow(
        flow_id="flow-tcp-01",
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.5",
        dst_ip="8.8.8.8",
        src_port=52341,
        dst_port=53,
        state=FlowState.ESTABLISHED,
        packets_forward=10,
        packets_reverse=8,
        bytes_forward=1200,
        bytes_reverse=3400,
        start_time=t0,
        last_seen=t0,
    )
    assert flow.total_packets == 18
    assert flow.total_bytes == 4600
    assert flow.duration_seconds >= 0.0


def test_nids_rule_validation() -> None:
    """Verify NIDSRule specification fields."""
    rule = NIDSRule(
        sid=10001,
        rev=1,
        name="ET SHELLCODE Possible /bin/sh invocation",
        protocol=PacketProtocol.TCP,
        src_ip="any",
        dst_ip="any",
        dst_port="any",
        content="/bin/sh",
        nocase=True,
        severity=AlertSeverity.CRITICAL,
        mitre_attack_id="T1059",
    )
    assert rule.sid == 10001
    assert rule.severity == AlertSeverity.CRITICAL
    assert rule.content == "/bin/sh"
    assert rule.nocase is True

    # Invalid rule: sid < 1
    with pytest.raises(ValidationError):
        NIDSRule(sid=0, name="Bad SID")


def test_nids_alert_model() -> None:
    """Verify NIDSAlert model serialization."""
    alert = NIDSAlert(
        anomaly_type=AnomalyType.DNS_TUNNELING,
        severity=AlertSeverity.HIGH,
        title="High Entropy DNS Tunneling Detected",
        description="Query exfiltration.bad.org has Shannon entropy 4.2",
        src_ip="192.168.1.50",
        dst_ip="1.1.1.1",
        dst_port=53,
        protocol=PacketProtocol.DNS,
        mitre_attack_id="T1071.004",
        metadata={"entropy": 4.2, "label_len": 45},
    )
    assert alert.alert_id is not None
    assert alert.anomaly_type == AnomalyType.DNS_TUNNELING
    assert alert.metadata["entropy"] == 4.2
