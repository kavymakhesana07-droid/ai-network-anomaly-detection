"""
Live Capture Ingestor - Domain logic for live packet capture via AF_PACKET.
No external dependencies (Scapy, Kafka, etc.) so unit tests run fast.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# Linux AF_PACKET constants
ETH_P_ALL = 0x0003  # Capture all protocols
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_MR_PROMISC = 1

# Ethernet header size
ETH_HLEN = 14


@dataclass(slots=True)
class LiveCaptureConfig:
    """Configuration for live capture, validated at construction."""

    interface: str
    promisc: bool = True
    snaplen: int = 65535
    buffer_size: int = 1 << 20  # 1 MiB ring buffer
    timeout_ms: int = 1000


@dataclass(slots=True)
class RawPacket:
    """A raw packet captured from the wire, before protocol parsing."""

    timestamp: float  # Unix epoch with microsecond precision
    interface: str
    data: bytes  # Full frame including Ethernet header
    length: int  # Captured length (<= snaplen)


# ioctl constant from <linux/sockios.h>
_SIOCGIFINDEX = 0x8933


def _interface_to_index(iface: str) -> int:
    """Convert interface name to kernel index using ioctl."""
    import fcntl

    ifr = struct.pack("16sH", iface.encode("ascii"), 0)
    try:
        res = fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), _SIOCGIFINDEX, ifr)
    except OSError as exc:
        raise ValueError("interface not found: " + iface) from exc
    return struct.unpack("16si", res)[1]  # type: ignore[no-any-return]


def create_raw_socket(config: LiveCaptureConfig) -> socket.socket:
    """
    Create and bind an AF_PACKET socket for the given interface.

    Returns a non-blocking socket ready for recv(). The caller owns the
    socket and must close it.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.setblocking(False)

    ifindex = _interface_to_index(config.interface)
    sock.bind((config.interface, ETH_P_ALL))

    # Promiscuous mode via PACKET_MR_PROMISC
    if config.promisc:
        mr = struct.pack(
            "IHH8s",
            ifindex,  # mr_ifindex
            PACKET_MR_PROMISC,  # mr_type
            0,  # mr_alen
            b"\x00" * 8,  # mr_address
        )
        sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr)

    # Increase kernel receive buffer
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, config.buffer_size)

    return sock


def parse_ethernet_header(frame: bytes) -> tuple[int, int, int, bytes] | None:
    """
    Parse Ethernet II header. Returns (src_mac, dst_mac, ethertype, payload)
    or None if frame is too short / not Ethernet II.
    """
    if len(frame) < ETH_HLEN:
        return None
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", frame[:ETH_HLEN])
    # ethertype > 1500 means Ethernet II (vs 802.3 length field)
    if ethertype <= 1500:
        return None
    return src_mac, dst_mac, ethertype, frame[ETH_HLEN:]


def parse_ipv4_header(payload: bytes) -> tuple[str, str, int, bytes] | None:
    """
    Parse IPv4 header. Returns (src_ip, dst_ip, protocol, transport_payload)
    or None if not IPv4 / malformed.
    """
    if len(payload) < 20:
        return None
    version_ihl = payload[0]
    version = version_ihl >> 4
    if version != 4:
        return None
    ihl = version_ihl & 0x0F
    header_len = ihl * 4
    if len(payload) < header_len:
        return None

    protocol = payload[9]
    src_ip = socket.inet_ntoa(payload[12:16])
    dst_ip = socket.inet_ntoa(payload[16:20])
    return src_ip, dst_ip, protocol, payload[header_len:]


def parse_tcp_udp_ports(transport: bytes, protocol: int) -> tuple[int, int] | None:
    """Parse source/dest port from TCP (6) or UDP (17) header."""
    if protocol not in (6, 17) or len(transport) < 4:
        return None
    src_port, dst_port = struct.unpack("!HH", transport[:4])
    return src_port, dst_port


def extract_flow_key(frame: bytes) -> tuple[str, str, int, int, int] | None:
    """
    Extract 5-tuple flow key from a raw Ethernet frame.
    Returns (src_ip, dst_ip, src_port, dst_port, protocol) or None.
    """
    eth = parse_ethernet_header(frame)
    if not eth:
        return None
    _, _, ethertype, ip_payload = eth
    if ethertype != 0x0800:  # IPv4 only for now
        return None

    ip = parse_ipv4_header(ip_payload)
    if not ip:
        return None
    src_ip, dst_ip, protocol, transport = ip

    ports = parse_tcp_udp_ports(transport, protocol)
    if not ports:
        return None
    src_port, dst_port = ports

    return src_ip, dst_ip, src_port, dst_port, protocol
