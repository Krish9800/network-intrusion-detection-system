"""SQLite WAL Persistence Engine for NIDS.

Stores packets, network flows, detection rules, and intrusion alerts with WAL
journaling and transactional safety.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from nids.models.enums import (
    AlertSeverity,
    AnomalyType,
    FlowState,
    PacketProtocol,
)
from nids.models.schemas import (
    DecodedPacket,
    NetworkFlow,
    NIDSAlert,
    NIDSRule,
)


class Database:
    """Manages SQLite connections and schema lifecycle for NIDS."""

    def __init__(self, db_path: Path | str, wal_mode: bool = True) -> None:
        self.db_path = Path(db_path)
        self.wal_mode = wal_mode
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.wal_mode:
            conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @contextmanager
    def session(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing transactional connection semantics."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Initialize database tables and indexes from schema file."""
        schema_path = Path(__file__).resolve().parent / "schema.sql"
        schema_sql = schema_path.read_text(encoding="utf-8")
        with self.session() as conn:
            conn.executescript(schema_sql)

    # -------------------------------------------------------------
    # Decoded Packets CRUD
    # -------------------------------------------------------------
    def save_packet(self, packet: DecodedPacket) -> None:
        """Persist a decoded packet."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO decoded_packets (
                    packet_id, timestamp, raw_length, protocol, src_mac, dst_mac,
                    src_ip, dst_ip, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack,
                    dns_query_name, http_method, http_path, payload_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.packet_id,
                    packet.timestamp.isoformat(),
                    packet.raw_length,
                    packet.protocol.value,
                    packet.src_mac,
                    packet.dst_mac,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.tcp_flags,
                    packet.tcp_seq,
                    packet.tcp_ack,
                    packet.dns_query_name,
                    packet.http_method,
                    packet.http_path,
                    packet.payload_preview,
                ),
            )

    # -------------------------------------------------------------
    # Network Flows CRUD
    # -------------------------------------------------------------
    def save_flow(self, flow: NetworkFlow) -> None:
        """Persist or update a network flow."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO network_flows (
                    flow_id, protocol, src_ip, dst_ip, src_port, dst_port, state,
                    packets_forward, packets_reverse, bytes_forward, bytes_reverse,
                    start_time, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.flow_id,
                    flow.protocol.value,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    flow.state.value,
                    flow.packets_forward,
                    flow.packets_reverse,
                    flow.bytes_forward,
                    flow.bytes_reverse,
                    flow.start_time.isoformat(),
                    flow.last_seen.isoformat(),
                ),
            )

    def list_flows(self, state: FlowState | None = None) -> list[NetworkFlow]:
        """List persisted network flows with optional state filtering."""
        query = "SELECT * FROM network_flows WHERE 1=1"
        params: list[Any] = []
        if state:
            query += " AND state = ?"
            params.append(state.value)
        query += " ORDER BY last_seen DESC"

        flows: list[NetworkFlow] = []
        with self.session() as conn:
            for row in conn.execute(query, params).fetchall():
                flows.append(
                    NetworkFlow(
                        flow_id=row["flow_id"],
                        protocol=PacketProtocol(row["protocol"]),
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        src_port=row["src_port"],
                        dst_port=row["dst_port"],
                        state=FlowState(row["state"]),
                        packets_forward=row["packets_forward"],
                        packets_reverse=row["packets_reverse"],
                        bytes_forward=row["bytes_forward"],
                        bytes_reverse=row["bytes_reverse"],
                        start_time=datetime.fromisoformat(row["start_time"]),
                        last_seen=datetime.fromisoformat(row["last_seen"]),
                    )
                )
        return flows

    # -------------------------------------------------------------
    # Detection Rules CRUD
    # -------------------------------------------------------------
    def save_rule(self, rule: NIDSRule) -> None:
        """Persist an intrusion detection rule."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nids_rules (
                    sid, rev, name, protocol, src_ip, dst_ip, src_port, dst_port,
                    content, nocase, offset, depth, regex, severity, mitre_attack_id, enabled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.sid,
                    rule.rev,
                    rule.name,
                    rule.protocol.value,
                    rule.src_ip,
                    rule.dst_ip,
                    rule.src_port,
                    rule.dst_port,
                    rule.content,
                    1 if rule.nocase else 0,
                    rule.offset,
                    rule.depth,
                    rule.regex,
                    rule.severity.value,
                    rule.mitre_attack_id,
                    1 if rule.enabled else 0,
                ),
            )

    def list_rules(self) -> list[NIDSRule]:
        """List all persisted NIDS rules."""
        rules: list[NIDSRule] = []
        with self.session() as conn:
            for row in conn.execute("SELECT * FROM nids_rules ORDER BY sid ASC").fetchall():
                rules.append(
                    NIDSRule(
                        sid=row["sid"],
                        rev=row["rev"],
                        name=row["name"],
                        protocol=PacketProtocol(row["protocol"]),
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        src_port=row["src_port"],
                        dst_port=row["dst_port"],
                        content=row["content"],
                        nocase=bool(row["nocase"]),
                        offset=row["offset"],
                        depth=row["depth"],
                        regex=row["regex"],
                        severity=AlertSeverity(row["severity"]),
                        mitre_attack_id=row["mitre_attack_id"],
                        enabled=bool(row["enabled"]),
                    )
                )
        return rules

    # -------------------------------------------------------------
    # NIDS Alerts CRUD
    # -------------------------------------------------------------
    def save_alert(self, alert: NIDSAlert) -> None:
        """Persist an intrusion alert."""
        with self.session() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nids_alerts (
                    alert_id, timestamp, anomaly_type, severity, title, description,
                    src_ip, dst_ip, src_port, dst_port, protocol, sid,
                    mitre_attack_id, payload_snippet, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.anomaly_type.value,
                    alert.severity.value,
                    alert.title,
                    alert.description,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.src_port,
                    alert.dst_port,
                    alert.protocol.value,
                    alert.sid,
                    alert.mitre_attack_id,
                    alert.payload_snippet,
                    json.dumps(alert.metadata),
                ),
            )

    def list_alerts(
        self,
        anomaly_type: AnomalyType | None = None,
        severity: AlertSeverity | None = None,
    ) -> list[NIDSAlert]:
        """List alerts with optional anomaly_type and severity filters."""
        query = "SELECT * FROM nids_alerts WHERE 1=1"
        params: list[Any] = []
        if anomaly_type:
            query += " AND anomaly_type = ?"
            params.append(anomaly_type.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        query += " ORDER BY timestamp DESC"

        alerts: list[NIDSAlert] = []
        with self.session() as conn:
            for row in conn.execute(query, params).fetchall():
                alerts.append(
                    NIDSAlert(
                        alert_id=row["alert_id"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        anomaly_type=AnomalyType(row["anomaly_type"]),
                        severity=AlertSeverity(row["severity"]),
                        title=row["title"],
                        description=row["description"],
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        src_port=row["src_port"],
                        dst_port=row["dst_port"],
                        protocol=PacketProtocol(row["protocol"]),
                        sid=row["sid"],
                        mitre_attack_id=row["mitre_attack_id"],
                        payload_snippet=row["payload_snippet"],
                        metadata=json.loads(row["metadata_json"]),
                    )
                )
        return alerts
