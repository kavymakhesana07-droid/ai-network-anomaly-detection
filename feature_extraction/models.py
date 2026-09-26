"""Pure data models for flow feature extraction.

Deliberately free of infrastructure imports (Kafka, Redis, Prometheus) so the
domain logic can be unit-tested with zero dependencies and no running services.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from math import log2

from pydantic import BaseModel, Field


# =============================================================================
# Raw input
# =============================================================================
class RawPacket(BaseModel):
    """A single parsed packet as produced by the ingestion layer."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    payload: bytes
    pcap_file: str
    packet_number: int


# =============================================================================
# Flow identity
# =============================================================================
@dataclass(frozen=True)
class FlowKey:
    """Direction-independent 5-tuple identifier.

    Both directions of a conversation map to the same key so that forward and
    reverse statistics can be accumulated on one object.
    """

    ip1: str
    ip2: str
    port1: int
    port2: int
    protocol: int

    @classmethod
    def from_packet(cls, pkt: RawPacket) -> FlowKey:
        if pkt.src_ip < pkt.dst_ip:
            return cls(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        return cls(pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)

    def __str__(self) -> str:
        return f"{self.ip1}:{self.port1}-{self.ip2}:{self.port2}-{self.protocol}"


# =============================================================================
# Mutable flow accumulator
# =============================================================================
@dataclass
class FlowState:
    """In-progress statistics for one bidirectional flow."""

    key: FlowKey
    start_time: float
    last_time: float
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    pkt_sizes: list[int] = field(default_factory=list)
    tcp_flags: dict[str, int] = field(default_factory=dict)
    dns_queries: list[bytes] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    tls_sni: list[str] = field(default_factory=list)
    payload_sample: bytes = b""

    def is_expired(self, now: float, timeout: int) -> bool:
        """A flow is expired once idle for longer than ``timeout`` seconds."""
        return (now - self.last_time) > timeout

    def is_forward(self, pkt: RawPacket) -> bool:
        """True when ``pkt`` travels along the canonical (ip1 -> ip2) direction."""
        return pkt.src_ip == self.key.ip1 and pkt.src_port == self.key.port1


# =============================================================================
# Feature vector
# =============================================================================
class FlowFeatures(BaseModel):
    """Standardized feature vector consumed by the detection models."""

    # Identity
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # Temporal
    start_time: float
    duration: float

    # Volume
    packets_total: int
    bytes_total: int
    packets_fwd: int
    packets_rev: int
    bytes_fwd: int
    bytes_rev: int

    # Rates
    packets_per_sec: float
    bytes_per_sec: float

    # Packet size distribution
    avg_pkt_size: float
    min_pkt_size: int
    max_pkt_size: int
    pkt_size_std: float

    # Directionality
    fwd_rev_packet_ratio: float
    fwd_rev_byte_ratio: float

    # TCP flags
    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_psh_count: int = 0
    tcp_urg_count: int = 0

    # Application layer
    dns_query_count: int = 0
    dns_unique_domains: int = 0
    http_request_count: int = 0
    http_unique_hosts: int = 0
    tls_handshake_count: int = 0
    tls_unique_sni: int = 0

    # Payload entropy
    payload_entropy: float = 0.0

    # Metadata
    pcap_source: str = ""
    extraction_time: float = Field(default_factory=lambda: datetime.now(tz=None).timestamp())


# =============================================================================
# Pure helpers
# =============================================================================
def compute_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0 - 8.0).

    High entropy suggests encrypted or compressed content; low entropy suggests
    plaintext or repetitive data. Useful as a lightweight encryption signal.
    """
    if not data:
        return 0.0
    freq: dict[int, int] = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    return -sum((count / length) * log2(count / length) for count in freq.values())


def summarize_flow(state: FlowState, pcap_source: str = "") -> FlowFeatures:
    """Build the feature vector for a completed (or expired) flow."""
    duration = max(state.last_time - state.start_time, 0.001)
    packets_total = state.packets_fwd + state.packets_rev
    bytes_total = state.bytes_fwd + state.bytes_rev

    sizes = state.pkt_sizes or [0]
    mean = sum(sizes) / len(sizes)
    variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)

    return FlowFeatures(
        flow_id=str(state.key),
        src_ip=state.key.ip1,
        dst_ip=state.key.ip2,
        src_port=state.key.port1,
        dst_port=state.key.port2,
        protocol=state.key.protocol,
        start_time=state.start_time,
        duration=duration,
        packets_total=packets_total,
        bytes_total=bytes_total,
        packets_fwd=state.packets_fwd,
        packets_rev=state.packets_rev,
        bytes_fwd=state.bytes_fwd,
        bytes_rev=state.bytes_rev,
        packets_per_sec=packets_total / duration,
        bytes_per_sec=bytes_total / duration,
        avg_pkt_size=mean,
        min_pkt_size=min(sizes),
        max_pkt_size=max(sizes),
        pkt_size_std=variance**0.5,
        fwd_rev_packet_ratio=state.packets_fwd / max(state.packets_rev, 1),
        fwd_rev_byte_ratio=state.bytes_fwd / max(state.bytes_rev, 1),
        tcp_syn_count=state.tcp_flags.get("SYN", 0),
        tcp_ack_count=state.tcp_flags.get("ACK", 0),
        tcp_fin_count=state.tcp_flags.get("FIN", 0),
        tcp_rst_count=state.tcp_flags.get("RST", 0),
        tcp_psh_count=state.tcp_flags.get("PSH", 0),
        tcp_urg_count=state.tcp_flags.get("URG", 0),
        dns_query_count=len(state.dns_queries),
        dns_unique_domains=len(set(state.dns_queries)),
        http_request_count=len(state.http_hosts),
        http_unique_hosts=len(set(state.http_hosts)),
        tls_handshake_count=len(state.tls_sni),
        tls_unique_sni=len(set(state.tls_sni)),
        payload_entropy=compute_entropy(state.payload_sample),
        pcap_source=pcap_source,
    )
