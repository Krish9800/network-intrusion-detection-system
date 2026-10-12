"""Statistical and Heuristic Network Anomaly Detectors.

Implements real-time detectors for:
1. TCP/UDP Port Scanning (unique destination ports tracking per source IP in sliding window)
2. TCP SYN Flood Attack (unanswered SYN rates and half-open ratio)
3. DNS Tunneling Exfiltration (Shannon entropy calculation on DNS query labels and length)
"""

import math
from collections import defaultdict, deque
from datetime import datetime, timedelta

from nids.models.enums import AlertSeverity, AnomalyType, PacketProtocol, TCPFlag
from nids.models.schemas import DecodedPacket, NIDSAlert


class AnomalyDetector:
    """Heuristic and statistical network intrusion detector."""

    def __init__(
        self,
        port_scan_threshold: int = 15,
        port_scan_window_seconds: int = 10,
        syn_flood_threshold: int = 50,
        dns_entropy_threshold: float = 3.8,
        dns_label_length_threshold: int = 30,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_seconds = port_scan_window_seconds
        self.syn_flood_threshold = syn_flood_threshold
        self.dns_entropy_threshold = dns_entropy_threshold
        self.dns_label_length_threshold = dns_label_length_threshold

        # Port scan state: src_ip -> deque of (timestamp, dst_ip, dst_port)
        self._port_scan_history: dict[str, deque[tuple[datetime, str, int]]] = defaultdict(deque)

        # SYN flood state: dst_ip -> deque of timestamps
        self._syn_flood_history: dict[str, deque[datetime]] = defaultdict(deque)

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy for a given string.

        H(X) = - sum(p(x) * log2(p(x)))
        """
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)
        freq: dict[str, int] = defaultdict(int)
        for char in data:
            freq[char] += 1

        for count in freq.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return entropy

    def detect_port_scan(self, packet: DecodedPacket) -> NIDSAlert | None:
        """Detect horizontal and vertical port scanning activity."""
        if not packet.src_ip or not packet.dst_port:
            return None

        # Focus on initial connection attempts (SYN or UDP probes)
        is_probe = False
        if (
            packet.protocol == PacketProtocol.TCP
            and packet.has_flag(TCPFlag.SYN)
            and not packet.has_flag(TCPFlag.ACK)
        ) or packet.protocol == PacketProtocol.UDP:
            is_probe = True

        if not is_probe:
            return None

        now = packet.timestamp
        cutoff = now - timedelta(seconds=self.port_scan_window_seconds)
        history = self._port_scan_history[packet.src_ip]

        # Evict old probes
        while history and history[0][0] < cutoff:
            history.popleft()

        target_dst = packet.dst_ip or "unknown"
        history.append((now, target_dst, packet.dst_port))

        unique_ports = {dst_port for _, _, dst_port in history}

        if len(unique_ports) >= self.port_scan_threshold:
            return NIDSAlert(
                anomaly_type=AnomalyType.PORT_SCAN,
                severity=AlertSeverity.HIGH,
                title="TCP/UDP Port Reconnaissance Scan Detected",
                description=(
                    f"Host {packet.src_ip} probed {len(unique_ports)} unique ports "
                    f"within {self.port_scan_window_seconds}s"
                ),
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                mitre_attack_id="T1046",
                metadata={
                    "unique_ports_count": len(unique_ports),
                    "window_seconds": self.port_scan_window_seconds,
                },
            )

        return None

    def detect_syn_flood(self, packet: DecodedPacket) -> NIDSAlert | None:
        """Detect TCP SYN flood attacks targeting destination assets."""
        if packet.protocol != PacketProtocol.TCP or not packet.dst_ip:
            return None

        # Check for pure SYN packet (SYN=1, ACK=0)
        if not packet.has_flag(TCPFlag.SYN) or packet.has_flag(TCPFlag.ACK):
            return None

        now = packet.timestamp
        cutoff = now - timedelta(seconds=1)  # 1-second rolling rate
        history = self._syn_flood_history[packet.dst_ip]

        while history and history[0] < cutoff:
            history.popleft()

        history.append(now)

        if len(history) >= self.syn_flood_threshold:
            return NIDSAlert(
                anomaly_type=AnomalyType.SYN_FLOOD,
                severity=AlertSeverity.CRITICAL,
                title="TCP SYN Flood Denial-of-Service Detected",
                description=(
                    f"Target host {packet.dst_ip} received {len(history)} SYN packets/sec "
                    f"(threshold: {self.syn_flood_threshold} pps)"
                ),
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol=PacketProtocol.TCP,
                mitre_attack_id="T1498.001",
                metadata={"syn_pps": len(history), "threshold": self.syn_flood_threshold},
            )

        return None

    def detect_dns_tunneling(self, packet: DecodedPacket) -> NIDSAlert | None:
        """Detect high-entropy DNS query tunneling used for data exfiltration."""
        if packet.protocol != PacketProtocol.DNS or not packet.dns_query_name:
            return None

        qname = packet.dns_query_name.lower()
        labels = qname.split(".")
        if not labels:
            return None

        # Check longest label (usually encoded data)
        subdomain = labels[0]
        entropy = self.calculate_shannon_entropy(subdomain)

        if (
            entropy >= self.dns_entropy_threshold
            and len(subdomain) >= self.dns_label_length_threshold
        ):
            return NIDSAlert(
                anomaly_type=AnomalyType.DNS_TUNNELING,
                severity=AlertSeverity.HIGH,
                title="High-Entropy DNS Tunneling / Exfiltration Detected",
                description=(
                    f"DNS query '{qname}' exhibits Shannon entropy {entropy:.2f} "
                    f"and label length {len(subdomain)}"
                ),
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=PacketProtocol.DNS,
                mitre_attack_id="T1071.004",
                payload_snippet=qname,
                metadata={
                    "entropy": round(entropy, 2),
                    "subdomain": subdomain,
                    "length": len(subdomain),
                },
            )

        return None

    def inspect_packet(self, packet: DecodedPacket) -> list[NIDSAlert]:
        """Run all heuristic and statistical anomaly checks on packet."""
        alerts: list[NIDSAlert] = []

        scan_alert = self.detect_port_scan(packet)
        if scan_alert:
            alerts.append(scan_alert)

        flood_alert = self.detect_syn_flood(packet)
        if flood_alert:
            alerts.append(flood_alert)

        tunnel_alert = self.detect_dns_tunneling(packet)
        if tunnel_alert:
            alerts.append(tunnel_alert)

        return alerts

    def clear(self) -> None:
        """Clear anomaly detection sliding buffers."""
        self._port_scan_history.clear()
        self._syn_flood_history.clear()
