"""Unit tests for SQLite WAL Persistence Engine in NIDS."""

from pathlib import Path

from nids.db.database import Database
from nids.models.enums import AlertSeverity, AnomalyType, FlowState, PacketProtocol
from nids.models.schemas import DecodedPacket, NetworkFlow, NIDSAlert, NIDSRule


def test_database_wal_initialization(temp_dir: Path) -> None:
    """Verify SQLite WAL mode and table initialization."""
    db = Database(temp_dir / "nids.db", wal_mode=True)
    with db.session() as conn:
        journal = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal.lower() == "wal"


def test_save_and_query_flow(temp_dir: Path) -> None:
    """Verify storing and retrieving NetworkFlow records."""
    db = Database(temp_dir / "flows.db")
    flow = NetworkFlow(
        flow_id="flow-12345",
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=4000,
        dst_port=80,
        state=FlowState.ESTABLISHED,
        packets_forward=5,
        packets_reverse=4,
    )
    db.save_flow(flow)

    flows = db.list_flows(state=FlowState.ESTABLISHED)
    assert len(flows) == 1
    assert flows[0].flow_id == "flow-12345"
    assert flows[0].packets_forward == 5


def test_save_and_list_rules(temp_dir: Path) -> None:
    """Verify saving and querying NIDSRules."""
    db = Database(temp_dir / "rules.db")
    rule = NIDSRule(
        sid=1001,
        name="Test Rule",
        protocol=PacketProtocol.TCP,
        content="/etc/passwd",
        severity=AlertSeverity.CRITICAL,
    )
    db.save_rule(rule)

    rules = db.list_rules()
    assert len(rules) == 1
    assert rules[0].sid == 1001
    assert rules[0].content == "/etc/passwd"


def test_save_and_filter_alerts(temp_dir: Path) -> None:
    """Verify saving and filtering intrusion alerts."""
    db = Database(temp_dir / "alerts.db")
    alert = NIDSAlert(
        anomaly_type=AnomalyType.PORT_SCAN,
        severity=AlertSeverity.HIGH,
        title="Port Scan",
        description="Host scanned 20 ports",
        src_ip="10.10.10.10",
        dst_ip="10.10.10.1",
        protocol=PacketProtocol.TCP,
    )
    db.save_alert(alert)

    # Filter by anomaly type
    alerts = db.list_alerts(anomaly_type=AnomalyType.PORT_SCAN)
    assert len(alerts) == 1
    assert alerts[0].title == "Port Scan"
    assert alerts[0].src_ip == "10.10.10.10"

    # Filter with non-matching severity
    empty = db.list_alerts(severity=AlertSeverity.LOW)
    assert len(empty) == 0


def test_save_packet(temp_dir: Path) -> None:
    """Verify saving decoded packet records."""
    db = Database(temp_dir / "packets.db")
    pkt = DecodedPacket(
        raw_length=64,
        protocol=PacketProtocol.ICMP,
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
    )
    db.save_packet(pkt)
    with db.session() as conn:
        row = conn.execute(
            "SELECT * FROM decoded_packets WHERE packet_id = ?", (pkt.packet_id,)
        ).fetchone()
        assert row is not None
        assert row["src_ip"] == "1.2.3.4"
