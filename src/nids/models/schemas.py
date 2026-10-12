"""Domain schemas and models for Network Intrusion Detection System."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nids.models.enums import (
    AlertSeverity,
    AnomalyType,
    FlowState,
    PacketProtocol,
    TCPFlag,
)


class DecodedPacket(BaseModel):
    """Normalized multi-layer decoded packet model."""

    model_config = ConfigDict(extra="allow", frozen=True)

    packet_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique packet identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Packet capture timestamp in UTC",
    )
    raw_length: int = Field(
        ...,
        ge=0,
        description="Wire length of packet in bytes",
    )
    protocol: PacketProtocol = Field(
        default=PacketProtocol.UNKNOWN,
        description="Primary transport protocol (TCP, UDP, ICMP)",
    )
    src_mac: str | None = Field(
        default=None,
        description="Source Ethernet MAC address",
    )
    dst_mac: str | None = Field(
        default=None,
        description="Destination Ethernet MAC address",
    )
    src_ip: str | None = Field(
        default=None,
        description="Source IPv4 or IPv6 address",
    )
    dst_ip: str | None = Field(
        default=None,
        description="Destination IPv4 or IPv6 address",
    )
    src_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source transport port",
    )
    dst_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination transport port",
    )
    tcp_flags: int = Field(
        default=0,
        description="TCP flag bitfield representation",
    )
    tcp_seq: int | None = Field(
        default=None,
        description="TCP sequence number",
    )
    tcp_ack: int | None = Field(
        default=None,
        description="TCP acknowledgement number",
    )
    dns_query_name: str | None = Field(
        default=None,
        description="Extracted DNS query domain name if applicable",
    )
    http_method: str | None = Field(
        default=None,
        description="HTTP request method (GET, POST) if applicable",
    )
    http_path: str | None = Field(
        default=None,
        description="HTTP request URI path if applicable",
    )
    payload_preview: str | None = Field(
        default=None,
        description="Sanitized ASCII/hex preview of application payload",
    )
    payload_bytes: bytes = Field(
        default=b"",
        description="Raw application layer payload bytes for deep inspection",
    )

    def has_flag(self, flag: TCPFlag) -> bool:
        """Check if a specific TCP flag bit is set."""
        return bool(self.tcp_flags & flag.value)


class NetworkFlow(BaseModel):
    """Bidirectional 5-tuple stateful network flow record."""

    model_config = ConfigDict(extra="allow")

    flow_id: str = Field(
        ...,
        description="Canonical 5-tuple hash identifier",
    )
    protocol: PacketProtocol = Field(
        ...,
        description="Transport protocol",
    )
    src_ip: str = Field(
        ...,
        description="Initiator / Source IP",
    )
    dst_ip: str = Field(
        ...,
        description="Responder / Destination IP",
    )
    src_port: int = Field(
        ...,
        ge=0,
        le=65535,
        description="Initiator port",
    )
    dst_port: int = Field(
        ...,
        ge=0,
        le=65535,
        description="Responder port",
    )
    state: FlowState = Field(
        default=FlowState.NEW,
        description="Current TCP / session state",
    )
    packets_forward: int = Field(
        default=0,
        ge=0,
        description="Packet count from source to destination",
    )
    packets_reverse: int = Field(
        default=0,
        ge=0,
        description="Packet count from destination to source",
    )
    bytes_forward: int = Field(
        default=0,
        ge=0,
        description="Total payload/wire bytes forward",
    )
    bytes_reverse: int = Field(
        default=0,
        ge=0,
        description="Total payload/wire bytes reverse",
    )
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of first observed packet",
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of most recent packet",
    )

    @property
    def total_packets(self) -> int:
        """Total bidirectional packets."""
        return self.packets_forward + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        """Total bidirectional bytes."""
        return self.bytes_forward + self.bytes_reverse

    @property
    def duration_seconds(self) -> float:
        """Duration of the flow in seconds."""
        return max(0.0, (self.last_seen - self.start_time).total_seconds())


class NIDSRule(BaseModel):
    """Declarative signature-based detection rule specification."""

    model_config = ConfigDict(extra="forbid")

    sid: int = Field(
        ...,
        ge=1,
        description="Suricata/Snort Signature ID",
    )
    rev: int = Field(
        default=1,
        ge=1,
        description="Rule revision number",
    )
    name: str = Field(
        ...,
        min_length=3,
        description="Descriptive alert title",
    )
    protocol: PacketProtocol = Field(
        default=PacketProtocol.TCP,
        description="Target protocol to inspect",
    )
    src_ip: str = Field(
        default="any",
        description="Source IP or CIDR",
    )
    dst_ip: str = Field(
        default="any",
        description="Destination IP or CIDR",
    )
    src_port: str = Field(
        default="any",
        description="Source port or range ('any', '80', '1024:65535')",
    )
    dst_port: str = Field(
        default="any",
        description="Destination port or range",
    )
    content: str | None = Field(
        default=None,
        description="Exact string or byte pattern to find in payload",
    )
    nocase: bool = Field(
        default=False,
        description="Case-insensitive content matching",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Payload byte offset to start matching",
    )
    depth: int | None = Field(
        default=None,
        ge=1,
        description="Maximum payload depth to inspect from offset",
    )
    regex: str | None = Field(
        default=None,
        description="Regular expression pattern to evaluate on payload",
    )
    severity: AlertSeverity = Field(
        default=AlertSeverity.MEDIUM,
        description="Alert severity level",
    )
    mitre_attack_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK technique (e.g., T1071.001)",
    )
    enabled: bool = Field(
        default=True,
        description="Whether rule is active",
    )


class NIDSAlert(BaseModel):
    """Structured intrusion alert record."""

    model_config = ConfigDict(extra="allow")

    alert_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique alert identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Alert detection timestamp in UTC",
    )
    anomaly_type: AnomalyType = Field(
        ...,
        description="Type of alert (signature, port scan, syn flood, dns tunneling)",
    )
    severity: AlertSeverity = Field(
        ...,
        description="Alert severity",
    )
    title: str = Field(
        ...,
        description="Alert summary title",
    )
    description: str = Field(
        ...,
        description="Detailed contextual alert description",
    )
    src_ip: str | None = Field(
        default=None,
        description="Offending source IP",
    )
    dst_ip: str | None = Field(
        default=None,
        description="Target destination IP",
    )
    src_port: int | None = Field(
        default=None,
        description="Source port",
    )
    dst_port: int | None = Field(
        default=None,
        description="Target port",
    )
    protocol: PacketProtocol = Field(
        default=PacketProtocol.UNKNOWN,
        description="Observed protocol",
    )
    sid: int | None = Field(
        default=None,
        description="Triggering rule SID if signature match",
    )
    mitre_attack_id: str | None = Field(
        default=None,
        description="Associated MITRE technique (e.g. T1046, T1071, T1498)",
    )
    payload_snippet: str | None = Field(
        default=None,
        description="Extracted payload snippet triggering alert",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional heuristic metrics (e.g. entropy, scan rate, packet count)",
    )
