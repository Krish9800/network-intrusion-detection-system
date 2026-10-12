"""Unit tests for SYN flood, port scan, and DNS tunneling anomaly detectors."""

from datetime import UTC, datetime, timedelta

from nids.detectors.anomaly_detector import AnomalyDetector
from nids.models.enums import AlertSeverity, AnomalyType, PacketProtocol, TCPFlag
from nids.models.schemas import DecodedPacket


def test_shannon_entropy_calculation() -> None:
    """Verify Shannon entropy math for repetitive vs random strings."""
    # Repetitive single character has 0 entropy
    assert AnomalyDetector.calculate_shannon_entropy("aaaaaaa") == 0.0

    # Low entropy typical domain name
    low_entropy = AnomalyDetector.calculate_shannon_entropy("google")
    assert low_entropy < 2.5

    # High entropy base64 encoded string
    high_entropy = AnomalyDetector.calculate_shannon_entropy("v3x9zK1mP8qL4wRtY7uI2oA5sD")
    assert high_entropy > 4.2


def test_port_scan_detection() -> None:
    """Verify sliding-window port scan detection."""
    detector = AnomalyDetector(port_scan_threshold=5, port_scan_window_seconds=10)
    now = datetime.now(UTC)

    alerts = []
    # Probe 5 distinct ports within 5 seconds from same host
    for port in range(1, 6):
        pkt = DecodedPacket(
            timestamp=now + timedelta(seconds=port),
            raw_length=60,
            protocol=PacketProtocol.TCP,
            src_ip="192.168.1.200",
            dst_ip="10.0.0.1",
            src_port=40000 + port,
            dst_port=port * 10,
            tcp_flags=TCPFlag.SYN.value,
        )
        res = detector.inspect_packet(pkt)
        if res:
            alerts.extend(res)

    assert len(alerts) >= 1
    scan_alert = alerts[0]
    assert scan_alert.anomaly_type == AnomalyType.PORT_SCAN
    assert scan_alert.severity == AlertSeverity.HIGH
    assert scan_alert.mitre_attack_id == "T1046"


def test_syn_flood_detection() -> None:
    """Verify TCP SYN flood detection exceeding pps threshold."""
    detector = AnomalyDetector(syn_flood_threshold=10)
    now = datetime.now(UTC)

    flood_alerts = []
    # Send 12 SYN packets in 0.5 seconds to single target
    for i in range(12):
        pkt = DecodedPacket(
            timestamp=now + timedelta(milliseconds=i * 40),
            raw_length=60,
            protocol=PacketProtocol.TCP,
            src_ip=f"198.51.100.{i}",
            dst_ip="10.0.0.80",
            src_port=1000 + i,
            dst_port=443,
            tcp_flags=TCPFlag.SYN.value,
        )
        res = detector.inspect_packet(pkt)
        if res:
            flood_alerts.extend(res)

    assert len(flood_alerts) >= 1
    flood_alert = flood_alerts[0]
    assert flood_alert.anomaly_type == AnomalyType.SYN_FLOOD
    assert flood_alert.severity == AlertSeverity.CRITICAL
    assert flood_alert.mitre_attack_id == "T1498.001"


def test_dns_tunneling_detection() -> None:
    """Verify high-entropy DNS tunneling detection."""
    detector = AnomalyDetector(dns_entropy_threshold=3.5, dns_label_length_threshold=25)
    tunneling_qname = "a8f3b9c2e1d7f4a5c6e8b2d1f9a3.c2tunnel.evil.org"

    pkt = DecodedPacket(
        raw_length=95,
        protocol=PacketProtocol.DNS,
        src_ip="192.168.1.55",
        dst_ip="8.8.8.8",
        src_port=53123,
        dst_port=53,
        dns_query_name=tunneling_qname,
    )

    alerts = detector.inspect_packet(pkt)
    assert len(alerts) == 1
    tunnel_alert = alerts[0]
    assert tunnel_alert.anomaly_type == AnomalyType.DNS_TUNNELING
    assert tunnel_alert.severity == AlertSeverity.HIGH
    assert tunnel_alert.mitre_attack_id == "T1071.004"
    assert "c2tunnel.evil.org" in str(tunnel_alert.payload_snippet)
