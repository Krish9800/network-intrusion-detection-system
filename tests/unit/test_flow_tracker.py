"""Unit tests for stateful 5-tuple flow tracker and TCP state machine."""

from datetime import UTC, datetime, timedelta

from nids.flow.tracker import FlowTracker
from nids.models.enums import FlowState, PacketProtocol, TCPFlag
from nids.models.schemas import DecodedPacket


def test_flow_canonical_id_bidirectional() -> None:
    """Verify bidirectional packets resolve to the exact same canonical flow ID."""
    tracker = FlowTracker()
    id_fwd, is_fwd = tracker.compute_flow_id("10.0.0.1", "10.0.0.2", 50000, 80, PacketProtocol.TCP)
    id_rev, is_rev = tracker.compute_flow_id("10.0.0.2", "10.0.0.1", 80, 50000, PacketProtocol.TCP)

    assert id_fwd == id_rev
    assert is_fwd is True
    assert is_rev is False


def test_tcp_three_way_handshake_and_teardown() -> None:
    """Verify TCP state machine through SYN -> SYN/ACK -> ACK -> FIN -> CLOSED."""
    tracker = FlowTracker()
    t0 = datetime.now(UTC)

    # 1. Client SYN -> Server
    p_syn = DecodedPacket(
        timestamp=t0,
        raw_length=74,
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=45000,
        dst_port=80,
        tcp_flags=TCPFlag.SYN.value,
    )
    flow = tracker.process_packet(p_syn)
    assert flow is not None
    assert flow.state == FlowState.SYN_SENT
    assert flow.packets_forward == 1

    # 2. Server SYN/ACK -> Client
    p_synack = DecodedPacket(
        timestamp=t0 + timedelta(milliseconds=10),
        raw_length=74,
        protocol=PacketProtocol.TCP,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=45000,
        tcp_flags=TCPFlag.SYN.value | TCPFlag.ACK.value,
    )
    flow = tracker.process_packet(p_synack)
    assert flow is not None
    assert flow.state == FlowState.SYN_RECV
    assert flow.packets_reverse == 1

    # 3. Client ACK -> Server (Established)
    p_ack = DecodedPacket(
        timestamp=t0 + timedelta(milliseconds=20),
        raw_length=66,
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=45000,
        dst_port=80,
        tcp_flags=TCPFlag.ACK.value,
    )
    flow = tracker.process_packet(p_ack)
    assert flow is not None
    assert flow.state == FlowState.ESTABLISHED
    assert flow.packets_forward == 2

    # 4. Client FIN -> Server
    p_fin = DecodedPacket(
        timestamp=t0 + timedelta(seconds=1),
        raw_length=66,
        protocol=PacketProtocol.TCP,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=45000,
        dst_port=80,
        tcp_flags=TCPFlag.FIN.value | TCPFlag.ACK.value,
    )
    flow = tracker.process_packet(p_fin)
    assert flow is not None
    assert flow.state == FlowState.FIN_WAIT

    # 5. Server ACK -> Client
    p_finack = DecodedPacket(
        timestamp=t0 + timedelta(seconds=1, milliseconds=10),
        raw_length=66,
        protocol=PacketProtocol.TCP,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=45000,
        tcp_flags=TCPFlag.ACK.value,
    )
    flow = tracker.process_packet(p_finack)
    assert flow is not None
    assert flow.state == FlowState.CLOSED


def test_tcp_rst_flag() -> None:
    """Verify RST flag immediately transitions flow to RESET."""
    tracker = FlowTracker()
    p_rst = DecodedPacket(
        raw_length=60,
        protocol=PacketProtocol.TCP,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1234,
        dst_port=80,
        tcp_flags=TCPFlag.RST.value,
    )
    flow = tracker.process_packet(p_rst)
    assert flow is not None
    assert flow.state == FlowState.RESET


def test_flow_expiration_eviction() -> None:
    """Verify eviction of inactive flows after timeout."""
    tracker = FlowTracker(flow_timeout_seconds=30)
    t0 = datetime.now(UTC)

    p1 = DecodedPacket(
        timestamp=t0,
        raw_length=60,
        protocol=PacketProtocol.UDP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1000,
        dst_port=2000,
    )
    tracker.process_packet(p1)
    assert tracker.active_flows_count() == 1

    # Before timeout: 0 evicted
    evicted_early = tracker.evict_expired_flows(t0 + timedelta(seconds=10))
    assert len(evicted_early) == 0
    assert tracker.active_flows_count() == 1

    # After timeout (40s later): flow evicted
    evicted_late = tracker.evict_expired_flows(t0 + timedelta(seconds=40))
    assert len(evicted_late) == 1
    assert tracker.active_flows_count() == 0

    # Non-IP packet yields None
    p_non_ip = DecodedPacket(raw_length=14, protocol=PacketProtocol.ETHERNET)
    assert tracker.process_packet(p_non_ip) is None
