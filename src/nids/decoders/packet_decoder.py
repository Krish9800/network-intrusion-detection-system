"""Binary Multi-Layer Packet Decoder.

Parses raw binary network frames into structured DecodedPacket models using Python's
native `struct` module without heavy external C dependencies.
Supports:
- Ethernet II (MAC addresses, EtherType)
- IPv4 (Header length, IPs, TTL, Protocol number)
- TCP (Source/destination ports, sequence, ack, flags bitfield, data offset)
- UDP (Source/destination ports, length)
- ICMP (Type, Code, Checksum)
- DNS (Transaction ID, query name parsing)
- HTTP (Request line method, path extraction)
"""

import socket
import struct
from datetime import UTC, datetime

from nids.models.enums import PacketProtocol
from nids.models.schemas import DecodedPacket


class PacketDecoderError(Exception):
    """Base exception for packet decoding errors."""


class PacketDecoder:
    """Zero-dependency multi-layer binary packet decoder."""

    @staticmethod
    def format_mac(mac_bytes: bytes) -> str:
        """Format 6 raw MAC bytes into canonical colon-separated string."""
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @staticmethod
    def decode_dns_name(payload: bytes, offset: int = 12) -> tuple[str | None, int]:
        """Decode a DNS query domain name from raw DNS payload."""
        labels: list[str] = []
        curr = offset
        try:
            while curr < len(payload):
                length = payload[curr]
                if length == 0:
                    curr += 1
                    break
                # Pointer compression check
                if (length & 0xC0) == 0xC0:
                    curr += 2
                    break
                curr += 1
                if curr + length > len(payload):
                    return None, curr
                label = payload[curr : curr + length].decode("ascii", errors="replace")
                labels.append(label)
                curr += length
            return ".".join(labels) if labels else None, curr
        except Exception:
            return None, curr

    @staticmethod
    def decode_http(payload: bytes) -> tuple[str | None, str | None]:
        """Attempt to extract HTTP method and path from application payload."""
        methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ")
        for m in methods:
            if payload.startswith(m):
                try:
                    first_line = payload.split(b"\r\n", 1)[0].decode("latin-1")
                    parts = first_line.split(" ", 2)
                    if len(parts) >= 2:
                        return parts[0], parts[1]
                except Exception:
                    return None, None
        return None, None

    def decode(self, raw_bytes: bytes, timestamp: datetime | None = None) -> DecodedPacket:
        """Decode raw Ethernet frame or IP packet into DecodedPacket."""
        ts = timestamp or datetime.now(UTC)
        raw_len = len(raw_bytes)

        if raw_len < 14:
            raise PacketDecoderError(f"Frame length ({raw_len}) is too short for Ethernet header")

        # 1. Ethernet Header (14 bytes)
        eth_header = raw_bytes[:14]
        dst_mac_raw, src_mac_raw, eth_type = struct.unpack("!6s6sH", eth_header)
        src_mac = self.format_mac(src_mac_raw)
        dst_mac = self.format_mac(dst_mac_raw)

        # EtherType: 0x0800 is IPv4
        if eth_type != 0x0800:
            return DecodedPacket(
                timestamp=ts,
                raw_length=raw_len,
                protocol=PacketProtocol.ETHERNET,
                src_mac=src_mac,
                dst_mac=dst_mac,
                payload_bytes=raw_bytes[14:],
            )

        # 2. IPv4 Header
        ip_offset = 14
        if len(raw_bytes) < ip_offset + 20:
            raise PacketDecoderError("Packet truncated in IPv4 header")

        ip_header_bytes = raw_bytes[ip_offset : ip_offset + 20]
        v_ihl, tos, total_len, ip_id, flags_frag, ttl, proto_num, cksum, src_ip_raw, dst_ip_raw = (
            struct.unpack("!BBHHHBBH4s4s", ip_header_bytes)
        )

        version = v_ihl >> 4
        ihl = (v_ihl & 0x0F) * 4
        if version != 4 or ihl < 20:
            raise PacketDecoderError("Invalid IPv4 version or IHL")

        src_ip = socket.inet_ntoa(src_ip_raw)
        dst_ip = socket.inet_ntoa(dst_ip_raw)
        transport_offset = ip_offset + ihl

        # 3. Transport Layer
        protocol = PacketProtocol.IPV4
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags = 0
        tcp_seq: int | None = None
        tcp_ack: int | None = None
        dns_query_name: str | None = None
        http_method: str | None = None
        http_path: str | None = None
        payload = b""

        # Protocol 6: TCP
        if proto_num == 6:
            protocol = PacketProtocol.TCP
            if len(raw_bytes) >= transport_offset + 20:
                tcp_header = raw_bytes[transport_offset : transport_offset + 20]
                sp, dp, seq, ack, data_offset_reserved, flags, window, chk, urg = struct.unpack(
                    "!HHIIBBHHH", tcp_header
                )
                src_port = sp
                dst_port = dp
                tcp_flags = flags
                tcp_seq = seq
                tcp_ack = ack
                tcp_data_offset = (data_offset_reserved >> 4) * 4
                app_offset = transport_offset + tcp_data_offset
                payload = raw_bytes[app_offset:]

                # Check for HTTP payload if common web ports
                if dst_port in (80, 8080) or src_port in (80, 8080):
                    m, p = self.decode_http(payload)
                    if m and p:
                        protocol = PacketProtocol.HTTP
                        http_method = m
                        http_path = p

        # Protocol 17: UDP
        elif proto_num == 17:
            protocol = PacketProtocol.UDP
            if len(raw_bytes) >= transport_offset + 8:
                udp_header = raw_bytes[transport_offset : transport_offset + 8]
                sp, dp, ulen, uchk = struct.unpack("!HHHH", udp_header)
                src_port = sp
                dst_port = dp
                payload = raw_bytes[transport_offset + 8 :]

                # Check for DNS (Port 53)
                if dst_port == 53 or src_port == 53:
                    protocol = PacketProtocol.DNS
                    qname, _ = self.decode_dns_name(payload)
                    dns_query_name = qname

        # Protocol 1: ICMP
        elif proto_num == 1:
            protocol = PacketProtocol.ICMP
            payload = raw_bytes[transport_offset:]

        payload_preview = payload[:64].decode("latin-1", errors="replace") if payload else None

        return DecodedPacket(
            timestamp=ts,
            raw_length=raw_len,
            protocol=protocol,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            dns_query_name=dns_query_name,
            http_method=http_method,
            http_path=http_path,
            payload_preview=payload_preview,
            payload_bytes=payload,
        )
