"""Unit tests for binary multi-layer packet decoder."""

import socket
import struct

import pytest

from nids.decoders.packet_decoder import PacketDecoder, PacketDecoderError
from nids.models.enums import PacketProtocol, TCPFlag


def make_eth_header(
    src: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    dst: bytes = b"\x00\x11\x22\x33\x44\x55",
    eth_type: int = 0x0800,
) -> bytes:
    """Build a 14-byte Ethernet II header."""
    return struct.pack("!6s6sH", dst, src, eth_type)


def make_ipv4_header(
    proto: int,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    payload_len: int = 0,
) -> bytes:
    """Build a 20-byte IPv4 header."""
    v_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    ip_id = 54321
    flags_frag = 0
    ttl = 64
    cksum = 0
    src_raw = socket.inet_aton(src_ip)
    dst_raw = socket.inet_aton(dst_ip)
    return struct.pack(
        "!BBHHHBBH4s4s",
        v_ihl,
        tos,
        total_len,
        ip_id,
        flags_frag,
        ttl,
        proto,
        cksum,
        src_raw,
        dst_raw,
    )


def test_decode_tcp_packet() -> None:
    """Verify decoding an Ethernet + IPv4 + TCP packet with payload."""
    decoder = PacketDecoder()
    eth = make_eth_header()
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    # TCP header (20 bytes): src_port=54321, dst_port=80, offset=5, flags=SYN|ACK
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        54321,
        80,
        1000,
        0,
        (5 << 4),
        TCPFlag.SYN.value | TCPFlag.ACK.value,
        65535,
        0,
        0,
    )
    ip = make_ipv4_header(proto=6, payload_len=len(tcp_hdr) + len(payload))
    raw = eth + ip + tcp_hdr + payload

    pkt = decoder.decode(raw)
    assert pkt.protocol == PacketProtocol.HTTP
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "10.0.0.1"
    assert pkt.src_port == 54321
    assert pkt.dst_port == 80
    assert pkt.has_flag(TCPFlag.SYN) is True
    assert pkt.has_flag(TCPFlag.ACK) is True
    assert pkt.http_method == "GET"
    assert pkt.http_path == "/index.html"
    assert pkt.payload_bytes == payload


def test_decode_udp_dns_packet() -> None:
    """Verify decoding UDP DNS query packet."""
    decoder = PacketDecoder()
    eth = make_eth_header()

    # DNS query wire format: 12-byte header + question for test.internal
    dns_header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    # Question: \x04test\x08internal\x00
    dns_question = b"\x04test\x08internal\x00\x00\x01\x00\x01"
    dns_payload = dns_header + dns_question

    udp_hdr = struct.pack("!HHHH", 49152, 53, 8 + len(dns_payload), 0)
    ip = make_ipv4_header(proto=17, payload_len=len(udp_hdr) + len(dns_payload))
    raw = eth + ip + udp_hdr + dns_payload

    pkt = decoder.decode(raw)
    assert pkt.protocol == PacketProtocol.DNS
    assert pkt.src_port == 49152
    assert pkt.dst_port == 53
    assert pkt.dns_query_name == "test.internal"


def test_decode_icmp_packet() -> None:
    """Verify decoding ICMP echo packet."""
    decoder = PacketDecoder()
    eth = make_eth_header()
    icmp_hdr = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)  # Echo Request
    icmp_payload = b"abcdefghijklmnopqrstuvw"
    ip = make_ipv4_header(proto=1, payload_len=len(icmp_hdr) + len(icmp_payload))
    raw = eth + ip + icmp_hdr + icmp_payload

    pkt = decoder.decode(raw)
    assert pkt.protocol == PacketProtocol.ICMP
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "10.0.0.1"


def test_decode_non_ipv4_ethernet() -> None:
    """Verify non-IPv4 EtherType (e.g. ARP 0x0806)."""
    decoder = PacketDecoder()
    raw = make_eth_header(eth_type=0x0806) + b"dummy arp payload"
    pkt = decoder.decode(raw)
    assert pkt.protocol == PacketProtocol.ETHERNET


def test_decode_truncated_packets() -> None:
    """Verify decoder raises PacketDecoderError on truncated frames."""
    decoder = PacketDecoder()
    with pytest.raises(PacketDecoderError, match="too short"):
        decoder.decode(b"\x00\x01\x02")

    # Valid eth but truncated IP
    eth = make_eth_header()
    with pytest.raises(PacketDecoderError, match="truncated in IPv4"):
        decoder.decode(eth + b"\x45\x00")
