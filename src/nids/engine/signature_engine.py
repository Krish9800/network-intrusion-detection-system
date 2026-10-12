"""Snort/Suricata Style Signature Detection Engine.

Matches decoded network packets against NIDSRules based on:
- Protocol (TCP, UDP, ICMP, DNS, HTTP)
- IP addresses / subnets ('any', exact match)
- Port numbers ('any', '80', '1024:65535')
- Payload content matching (exact byte/string, offset, depth, nocase)
- Regular expression patterns on payload
"""

import re

from nids.models.enums import AnomalyType, PacketProtocol
from nids.models.schemas import DecodedPacket, NIDSAlert, NIDSRule


class SignatureEngine:
    """Evaluates decoded packets against declarative NIDS signatures."""

    def __init__(self, rules: list[NIDSRule] | None = None) -> None:
        self.rules: list[NIDSRule] = [r for r in (rules or []) if r.enabled]

    def add_rule(self, rule: NIDSRule) -> None:
        """Register a new detection rule."""
        if rule.enabled:
            self.rules.append(rule)

    @staticmethod
    def match_ip(rule_ip: str, packet_ip: str | None) -> bool:
        """Check IP match supporting 'any' or exact match."""
        if rule_ip == "any":
            return True
        if not packet_ip:
            return False
        return rule_ip == packet_ip

    @staticmethod
    def match_port(rule_port: str, packet_port: int | None) -> bool:
        """Check port match supporting 'any', single integer '80', or range '1024:65535'."""
        if rule_port == "any":
            return True
        if packet_port is None:
            return False

        if ":" in rule_port:
            parts = rule_port.split(":", 1)
            try:
                low = int(parts[0]) if parts[0] else 0
                high = int(parts[1]) if parts[1] else 65535
                return low <= packet_port <= high
            except ValueError:
                return False

        try:
            return int(rule_port) == packet_port
        except ValueError:
            return False

    @staticmethod
    def match_content(
        rule: NIDSRule,
        payload: bytes,
    ) -> tuple[bool, str | None]:
        """Search payload for exact content string according to offset, depth, and case."""
        if not rule.content:
            return True, None

        if len(payload) < rule.offset:
            return False, None

        search_slice = payload[rule.offset :]
        if rule.depth is not None:
            search_slice = search_slice[: rule.depth]

        target_bytes = rule.content.encode("latin-1")

        if rule.nocase:
            search_slice_cmp = search_slice.lower()
            target_cmp = target_bytes.lower()
            idx = search_slice_cmp.find(target_cmp)
        else:
            idx = search_slice.find(target_bytes)

        if idx != -1:
            snippet = search_slice[idx : idx + len(target_bytes) + 32].decode(
                "latin-1", errors="replace"
            )
            return True, snippet

        return False, None

    @staticmethod
    def match_regex(rule: NIDSRule, payload: bytes) -> tuple[bool, str | None]:
        """Evaluate regular expression pattern against payload."""
        if not rule.regex:
            return True, None

        flags = re.IGNORECASE if rule.nocase else 0
        try:
            payload_str = payload.decode("latin-1", errors="replace")
            match = re.search(rule.regex, payload_str, flags)
            if match:
                return True, match.group(0)[:64]
            return False, None
        except re.error:
            return False, None

    def match_packet(self, packet: DecodedPacket) -> list[NIDSAlert]:
        """Evaluate a packet against all rules and return triggered alerts."""
        alerts: list[NIDSAlert] = []

        for rule in self.rules:
            # 1. Protocol check
            if (
                rule.protocol != PacketProtocol.UNKNOWN
                and rule.protocol != packet.protocol
                and not (
                    (rule.protocol == PacketProtocol.TCP and packet.protocol == PacketProtocol.HTTP)
                    or (
                        rule.protocol == PacketProtocol.UDP
                        and packet.protocol == PacketProtocol.DNS
                    )
                )
            ):
                continue

            # 2. IP checks
            if not self.match_ip(rule.src_ip, packet.src_ip):
                continue
            if not self.match_ip(rule.dst_ip, packet.dst_ip):
                continue

            # 3. Port checks
            if not self.match_port(rule.src_port, packet.src_port):
                continue
            if not self.match_port(rule.dst_port, packet.dst_port):
                continue

            # 4. Content payload search
            content_matched, snippet = self.match_content(rule, packet.payload_bytes)
            if not content_matched:
                continue

            # 5. Regex payload search
            regex_matched, regex_snippet = self.match_regex(rule, packet.payload_bytes)
            if not regex_matched:
                continue

            final_snippet = snippet or regex_snippet or packet.payload_preview

            # Trigger alert
            alert = NIDSAlert(
                anomaly_type=AnomalyType.SIGNATURE_MATCH,
                severity=rule.severity,
                title=f"[SID:{rule.sid}] {rule.name}",
                description=f"Signature match on {packet.protocol.value} payload",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                sid=rule.sid,
                mitre_attack_id=rule.mitre_attack_id,
                payload_snippet=final_snippet,
            )
            alerts.append(alert)

        return alerts
