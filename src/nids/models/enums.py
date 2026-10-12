"""Protocol and state enumerations for Network Intrusion Detection System."""

from enum import IntFlag, StrEnum


class PacketProtocol(StrEnum):
    """Network and transport protocols decoded by NIDS."""

    ETHERNET = "ethernet"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    UNKNOWN = "unknown"


class TCPFlag(IntFlag):
    """Standard TCP header flags bitfield representation."""

    NONE = 0
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class FlowState(StrEnum):
    """Stateful 5-tuple TCP / session tracking state."""

    NEW = "new"
    SYN_SENT = "syn_sent"
    SYN_RECV = "syn_recv"
    ESTABLISHED = "established"
    FIN_WAIT = "fin_wait"
    CLOSED = "closed"
    RESET = "reset"


class AlertSeverity(StrEnum):
    """Normalized alert severity levels aligned with SIEM standards."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(StrEnum):
    """Categories of detected network anomalies."""

    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DNS_TUNNELING = "dns_tunneling"
    SIGNATURE_MATCH = "signature_match"
    PAYLOAD_ANOMALY = "payload_anomaly"
