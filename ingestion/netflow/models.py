"""
NetFlow/sFlow/IPFIX Ingestor - Domain logic for flow record parsing.
No external dependencies so unit tests run fast.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class FlowProtocol(IntEnum):
    """IANA protocol numbers commonly seen in flow records."""

    TCP = 6
    UDP = 17
    ICMP = 1
    ICMPV6 = 58


class FlowDirection(IntEnum):
    """Flow direction relative to the exporter."""

    INGRESS = 0
    EGRESS = 1


@dataclass(slots=True)
class FlowRecord:
    """
    Normalized flow record, protocol-agnostic (NetFlow v5/v9/IPFIX, sFlow).
    Fields present in all major flow export formats.
    """

    # Time
    flow_start: float  # Unix epoch seconds (may have fractional)
    flow_end: float  # Unix epoch seconds
    # Network
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # IANA protocol number
    # Volume
    packets: int
    bytes: int
    # Metadata
    input_snmp: int  # Input interface index
    output_snmp: int  # Output interface index
    src_as: int  # Source AS number
    dst_as: int  # Destination AS number
    # TCP flags (OR'd over all packets in flow)
    tcp_flags: int
    # Exporter
    exporter_ip: str
    engine_type: int
    engine_id: int
    # Optional vendor extensions
    vendor_props: dict[str, str]


@dataclass(slots=True)
class NetFlowConfig:
    """Configuration for the NetFlow/sFlow/IPFIX listener."""

    listen_ip: str = "0.0.0.0"  # noqa: S104 - binding to all interfaces is intentional
    listen_port: int = 2055  # NetFlow/IPFIX default
    sflow_port: int = 6343  # sFlow default
    max_packet_size: int = 65535
    worker_count: int = 4
    # Template refresh
    template_timeout: int = 3600  # Seconds before template expires


def flow_key(record: FlowRecord) -> str:
    """Canonical flow key: 'src_ip:src_port->dst_ip:dst_port/proto'."""
    return f"{record.src_ip}:{record.src_port}->{record.dst_ip}:{record.dst_port}/{record.protocol}"


def reverse_flow_key(record: FlowRecord) -> str:
    """Flow key with endpoints swapped (for bidirectional matching)."""
    return f"{record.dst_ip}:{record.dst_port}->{record.src_ip}:{record.src_port}/{record.protocol}"


def protocol_name(proto: int) -> str:
    """Human-readable protocol name."""
    try:
        return FlowProtocol(proto).name
    except ValueError:
        return str(proto)


def tcp_flag_names(flags: int) -> list[str]:
    """Decode TCP flags bitmask to names."""
    names = []
    flag_map = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
        0x40: "ECE",
        0x80: "CWR",
    }
    for bit, name in flag_map.items():
        if flags & bit:
            names.append(name)
    return names


def normalize_ipv4_mapped_ipv6(ip: str) -> str:
    """
    Convert IPv4-mapped IPv6 address (::ffff:1.2.3.4) to plain IPv4.
    NetFlow v9/IPFIX sometimes exports IPv4 this way.
    """
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


@dataclass(slots=True)
class TemplateRecord:
    """NetFlow v9 / IPFIX template cache entry."""

    template_id: int
    field_spec: list[tuple[int, int]]  # List of (field_type, field_length)
    scope_field_count: int = 0  # For IPFIX scope fields
    created_at: float = 0.0
