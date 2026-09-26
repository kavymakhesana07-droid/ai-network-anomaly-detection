"""
Unified Feature Extraction Pipeline
Consumes raw packets/flows from Kafka, extracts standardized features, publishes to features topic.
"""

import asyncio
import signal
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    input_topic: str = Field(default="raw.packets", alias="INPUT_TOPIC")
    output_topic: str = Field(default="features.flows", alias="OUTPUT_TOPIC")
    consumer_group: str = Field(default="feature-extractor", alias="CONSUMER_GROUP")

    # Flow timeout
    flow_timeout: int = Field(default=300, alias="FLOW_TIMEOUT")  # seconds
    max_flows: int = Field(default=100000, alias="MAX_FLOWS")

    # Batching
    batch_size: int = Field(default=100, alias="BATCH_SIZE")
    flush_interval: float = Field(default=1.0, alias="FLUSH_INTERVAL")


# =============================================================================
# Data Models
# =============================================================================

class RawPacket(BaseModel):
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


@dataclass
class FlowKey:
    """5-tuple flow identifier (normalized: lower IP first)"""
    ip1: str
    ip2: str
    port1: int
    port2: int
    protocol: int

    @classmethod
    def from_packet(cls, pkt: RawPacket) -> "FlowKey":
        # Normalize: sort IPs lexicographically for bidirectional flow tracking
        if pkt.src_ip < pkt.dst_ip:
            return cls(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        else:
            return cls(pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)


@dataclass
class FlowState:
    """Accumulated flow statistics"""
    key: FlowKey
    start_time: float
    last_time: float
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    tcp_flags: dict = field(default_factory=dict)
    dns_queries: list = field(default_factory=list)
    http_hosts: list = field(default_factory=list)
    tls_sni: list = field(default_factory=list)
    payload_sample: bytes = b""

    def is_expired(self, now: float, timeout: int) -> bool:
        return (now - self.last_time) > timeout


class FlowFeatures(BaseModel):
    """Standardized feature vector for ML models"""
    # Flow identity
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

    # Packet sizes
    avg_pkt_size: float
    min_pkt_size: int
    max_pkt_size: int
    pkt_size_std: float

    # Directionality
    fwd_rev_packet_ratio: float
    fwd_rev_byte_ratio: float

    # TCP flags (if TCP)
    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_psh_count: int = 0
    tcp_urg_count: int = 0

    # DNS
    dns_query_count: int = 0
    dns_unique_domains: int = 0

    # HTTP
    http_request_count: int = 0
    http_unique_hosts: int = 0

    # TLS
    tls_handshake_count: int = 0
    tls_unique_sni: int = 0

    # Payload entropy (truncated)
    payload_entropy: float = 0.0

    # Metadata
    pcap_source: str = ""
    extraction_time: float = Field(default_factory=lambda: datetime.utcnow().timestamp())


# =============================================================================
# Feature Extractor
# =============================================================================

class FeatureExtractor:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.consumer: Optional[AIOKafkaConsumer] = None
        self.producer: Optional[AIOKafkaProducer] = None
        self.flows: dict[FlowKey, FlowState] = {}
        self.running = False
        self.processed = 0
        self.exported = 0

    async def start(self):
        self.consumer = AIOKafkaConsumer(
            self.settings.input_topic,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id=self.settings.consumer_group,
            value_deserializer=lambda m: RawPacket.model_validate_json(m),
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        await self.consumer.start()

        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            value_serializer=lambda v: v.model_dump_json().encode(),
            acks="all",
        )
        await self.producer.start()

        logger.info("Feature extractor started", input=self.settings.input_topic, output=self.settings.output_topic)

    async def stop(self):
        self.running = False
        # Export remaining flows
        await self._export_all_flows()
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        logger.info("Feature extractor stopped", processed=self.processed, exported=self.exported)

    async def run(self):
        self.running = True
        last_flush = asyncio.get_event_loop().time()
        last_cleanup = last_flush

        async for msg in self.consumer:
            if not self.running:
                break

            pkt = msg.value
            self.processed += 1
            await self._process_packet(pkt)

            # Periodic flush
            now = asyncio.get_event_loop().time()
            if now - last_flush >= self.settings.flush_interval:
                await self._export_expired_flows(now)
                last_flush = now

            # Periodic cleanup
            if now - last_cleanup >= 60:
                await self._cleanup_expired_flows(now)
                last_cleanup = now

    async def _process_packet(self, pkt: RawPacket):
        key = FlowKey.from_packet(pkt)
        is_forward = (pkt.src_ip == key.ip1 and pkt.src_port == key.port1)

        if key not in self.flows:
            if len(self.flows) >= self.settings.max_flows:
                await self._export_expired_flows(asyncio.get_event_loop().time())
            self.flows[key] = FlowState(key=key, start_time=pkt.timestamp, last_time=pkt.timestamp)

        flow = self.flows[key]
        flow.last_time = pkt.timestamp

        if is_forward:
            flow.packets_fwd += 1
            flow.bytes_fwd += pkt.length
        else:
            flow.packets_rev += 1
            flow.bytes_rev += pkt.length

        # Payload sample (first 256 bytes)
        if not flow.payload_sample and pkt.payload:
            flow.payload_sample = pkt.payload[:256]

        # Parse application layer (simplified - real impl would use dpkt/scapy)
        self._parse_app_layer(flow, pkt)

    def _parse_app_layer(self, flow: FlowState, pkt: RawPacket):
        """Extract DNS, HTTP, TLS features from payload"""
        payload = pkt.payload
        if not payload:
            return

        # DNS (port 53)
        if pkt.src_port == 53 or pkt.dst_port == 53:
            if b"\x00\x00\x01\x00\x01" in payload[:12]:  # DNS query
                flow.dns_queries.append(payload[:64])

        # HTTP (port 80, 8080)
        if pkt.dst_port in (80, 8080, 8000) and payload.startswith(b"GET ") or payload.startswith(b"POST "):
            host_start = payload.find(b"Host: ")
            if host_start != -1:
                host_end = payload.find(b"\r\n", host_start)
                if host_end != -1:
                    flow.http_hosts.append(payload[host_start+6:host_end].decode(errors="ignore"))

        # TLS SNI (port 443)
        if pkt.dst_port == 443 and len(payload) > 5 and payload[0] == 0x16:  # Handshake
            # Simplified - real impl would parse ClientHello
            flow.tls_sni.append("sni_placeholder")

    def _compute_features(self, flow: FlowState, now: float) -> FlowFeatures:
        duration = max(flow.last_time - flow.start_time, 0.001)
        pkts_total = flow.packets_fwd + flow.packets_rev
        bytes_total = flow.bytes_fwd + flow.bytes_rev

        return FlowFeatures(
            flow_id=f"{flow.key.ip1}:{flow.key.port1}-{flow.key.ip2}:{flow.key.port2}-{flow.key.protocol}",
            src_ip=flow.key.ip1,
            dst_ip=flow.key.ip2,
            src_port=flow.key.port1,
            dst_port=flow.key.port2,
            protocol=flow.key.protocol,
            start_time=flow.start_time,
            duration=duration,
            packets_total=pkts_total,
            bytes_total=bytes_total,
            packets_fwd=flow.packets_fwd,
            packets_rev=flow.packets_rev,
            bytes_fwd=flow.bytes_fwd,
            bytes_rev=flow.bytes_rev,
            packets_per_sec=pkts_total / duration,
            bytes_per_sec=bytes_total / duration,
            avg_pkt_size=bytes_total / pkts_total if pkts_total > 0 else 0,
            min_pkt_size=0,  # Would track in FlowState
            max_pkt_size=0,
            pkt_size_std=0.0,
            fwd_rev_packet_ratio=flow.packets_fwd / max(flow.packets_rev, 1),
            fwd_rev_byte_ratio=flow.bytes_fwd / max(flow.bytes_rev, 1),
            tcp_syn_count=flow.tcp_flags.get("SYN", 0),
            tcp_ack_count=flow.tcp_flags.get("ACK", 0),
            tcp_fin_count=flow.tcp_flags.get("FIN", 0),
            tcp_rst_count=flow.tcp_flags.get("RST", 0),
            tcp_psh_count=flow.tcp_flags.get("PSH", 0),
            tcp_urg_count=flow.tcp_flags.get("URG", 0),
            dns_query_count=len(flow.dns_queries),
            dns_unique_domains=len(set(q for q in flow.dns_queries)),
            http_request_count=len(flow.http_hosts),
            http_unique_hosts=len(set(flow.http_hosts)),
            tls_handshake_count=len(flow.tls_sni),
            tls_unique_sni=len(set(flow.tls_sni)),
            payload_entropy=self._entropy(flow.payload_sample) if flow.payload_sample else 0.0,
        )

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        from math import log2
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        return -sum((c/len(data)) * log2(c/len(data)) for c in freq.values())

    async def _export_expired_flows(self, now: float):
        expired = [k for k, v in self.flows.items() if v.is_expired(now, self.settings.flow_timeout)]
        for key in expired:
            flow = self.flows.pop(key)
            features = self._compute_features(flow, now)
            await self._send_features(features)
            self.exported += 1

    async def _export_all_flows(self):
        now = asyncio.get_event_loop().time()
        for key in list(self.flows.keys()):
            flow = self.flows.pop(key)
            features = self._compute_features(flow, now)
            await self._send_features(features)
            self.exported += 1

    async def _cleanup_expired_flows(self, now: float):
        """Force-expire very old flows to prevent memory leak"""
        force_timeout = self.settings.flow_timeout * 10
        expired = [k for k, v in self.flows.items() if v.is_expired(now, force_timeout)]
        for key in expired:
            flow = self.flows.pop(key)
            features = self._compute_features(flow, now)
            await self._send_features(features)
            self.exported += 1
        if expired:
            logger.warning("Force-expired flows", count=len(expired))

    async def _send_features(self, features: FlowFeatures):
        if self.producer:
            await self.producer.send_and_wait(self.settings.output_topic, features)


async def main():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    settings = Settings()
    extractor = FeatureExtractor(settings)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(extractor.stop()))

    await extractor.start()
    try:
        await extractor.run()
    finally:
        await extractor.stop()


if __name__ == "__main__":
    asyncio.run(main())