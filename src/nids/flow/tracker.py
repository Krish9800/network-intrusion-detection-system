"""Stateful 5-Tuple Network Flow Tracker.

Tracks bidirectional network sessions keyed on canonical 5-tuples:
(src_ip, dst_ip, src_port, dst_port, protocol).
Maintains:
- TCP connection state machine (NEW -> SYN_SENT -> SYN_RECV -> ESTABLISHED -> FIN_WAIT -> CLOSED)
- Forward / Reverse packet and byte counters
- Inactivity timeouts and flow table eviction
"""

import hashlib
from datetime import UTC, datetime, timedelta

from nids.models.enums import FlowState, PacketProtocol, TCPFlag
from nids.models.schemas import DecodedPacket, NetworkFlow


class FlowTracker:
    """Stateful 5-tuple network flow tracker with TCP state machine."""

    def __init__(self, flow_timeout_seconds: int = 120, max_active_flows: int = 50_000) -> None:
        self.flow_timeout_seconds = flow_timeout_seconds
        self.max_active_flows = max_active_flows

        # Canonical flow_id -> NetworkFlow
        self._flows: dict[str, NetworkFlow] = {}

    @staticmethod
    def compute_flow_id(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: PacketProtocol,
    ) -> tuple[str, bool]:
        """Compute canonical 5-tuple hash and identify direction.

        Returns:
            Tuple `(flow_id, is_forward)` where `is_forward` is True if the packet
            matches the canonical initiator ordering, or False if reverse.
        """
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}:{protocol.value}"
            is_forward = True
        else:
            key = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}:{protocol.value}"
            is_forward = False

        flow_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return flow_hash, is_forward

    def update_tcp_state(self, current_state: FlowState, flags: int, is_forward: bool) -> FlowState:
        """Advance TCP handshake and teardown state machine based on flags."""
        is_syn = bool(flags & TCPFlag.SYN.value)
        is_ack = bool(flags & TCPFlag.ACK.value)
        is_fin = bool(flags & TCPFlag.FIN.value)
        is_rst = bool(flags & TCPFlag.RST.value)

        if is_rst:
            return FlowState.RESET

        if current_state == FlowState.NEW:
            if is_syn and not is_ack:
                return FlowState.SYN_SENT
            if is_syn and is_ack:
                return FlowState.SYN_RECV
            return FlowState.ESTABLISHED

        if current_state == FlowState.SYN_SENT:
            if is_syn and is_ack and not is_forward:
                return FlowState.SYN_RECV
            if is_ack and is_forward:
                return FlowState.ESTABLISHED

        if current_state == FlowState.SYN_RECV and is_ack and is_forward:
            return FlowState.ESTABLISHED

        if current_state == FlowState.ESTABLISHED and is_fin:
            return FlowState.FIN_WAIT

        if current_state == FlowState.FIN_WAIT and (is_ack or is_fin):
            return FlowState.CLOSED

        return current_state

    def process_packet(self, packet: DecodedPacket) -> NetworkFlow | None:
        """Update or create a network flow record from an incoming packet.

        Returns:
            Updated NetworkFlow instance, or None if packet lacks IP/port headers.
        """
        if not packet.src_ip or not packet.dst_ip:
            return None

        src_p = packet.src_port or 0
        dst_p = packet.dst_port or 0
        flow_id, is_forward = self.compute_flow_id(
            packet.src_ip, packet.dst_ip, src_p, dst_p, packet.protocol
        )

        flow = self._flows.get(flow_id)
        ts = packet.timestamp

        if not flow:
            # Enforce max table size
            if len(self._flows) >= self.max_active_flows:
                self.evict_expired_flows(ts)

            init_state = FlowState.NEW
            if packet.protocol == PacketProtocol.TCP:
                init_state = self.update_tcp_state(FlowState.NEW, packet.tcp_flags, is_forward=True)

            flow = NetworkFlow(
                flow_id=flow_id,
                protocol=packet.protocol,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=src_p,
                dst_port=dst_p,
                state=init_state,
                packets_forward=1,
                packets_reverse=0,
                bytes_forward=packet.raw_length,
                bytes_reverse=0,
                start_time=ts,
                last_seen=ts,
            )
            self._flows[flow_id] = flow
            return flow

        # Existing flow: determine direction relative to initiator (flow.src_ip / src_port)
        is_initiator = packet.src_ip == flow.src_ip and src_p == flow.src_port
        flow.last_seen = ts

        if is_initiator:
            flow.packets_forward += 1
            flow.bytes_forward += packet.raw_length
        else:
            flow.packets_reverse += 1
            flow.bytes_reverse += packet.raw_length

        if packet.protocol == PacketProtocol.TCP:
            flow.state = self.update_tcp_state(
                flow.state, packet.tcp_flags, is_forward=is_initiator
            )

        return flow

    def evict_expired_flows(self, current_time: datetime | None = None) -> list[NetworkFlow]:
        """Evict and return flows that exceeded the inactivity timeout."""
        now = current_time or datetime.now(UTC)
        cutoff = now - timedelta(seconds=self.flow_timeout_seconds)

        expired_ids: list[str] = []
        expired_flows: list[NetworkFlow] = []

        for f_id, flow in self._flows.items():
            if flow.last_seen < cutoff:
                expired_ids.append(f_id)
                expired_flows.append(flow)

        for f_id in expired_ids:
            del self._flows[f_id]

        return expired_flows

    def get_flow(self, flow_id: str) -> NetworkFlow | None:
        """Lookup active flow by flow_id."""
        return self._flows.get(flow_id)

    def active_flows_count(self) -> int:
        """Count of currently active in-memory flows."""
        return len(self._flows)

    def clear(self) -> None:
        """Clear all active flows."""
        self._flows.clear()
