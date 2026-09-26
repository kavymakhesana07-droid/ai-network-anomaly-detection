"""Unified Feature Extraction Service.

Consumes raw packets from Kafka, aggregates them into bidirectional flows,
and publishes standardized feature vectors for the detection tier.

Domain logic lives in ``models.py`` (dependency-free); this module is the
service shell that wires it to Kafka, Prometheus, and structured logging.
"""

from __future__ import annotations

import asyncio
import signal

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic_settings import BaseSettings, SettingsConfigDict

from feature_extraction.models import (
    FlowKey,
    FlowState,
    RawPacket,
    summarize_flow,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    kafka_brokers: str = "localhost:9092"
    input_topic: str = "raw.packets"
    output_topic: str = "features.flows"
    consumer_group: str = "feature-extractor"

    flow_timeout: int = 300
    max_flows: int = 100_000

    batch_size: int = 100
    flush_interval: float = 1.0
    cleanup_interval: float = 60.0
    hard_expiry_multiplier: int = 10

    metrics_port: int = 9090


class FeatureExtractor:
    """Aggregates packets into flows and emits feature vectors."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.consumer: AIOKafkaConsumer | None = None
        self.producer: AIOKafkaProducer | None = None
        self.flows: dict[FlowKey, FlowState] = {}
        self.running = False

        self.packets_processed = 0
        self.packets_skipped = 0
        self.flows_exported = 0
        self.publish_errors = 0

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
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

        logger.info(
            "feature extractor started",
            input_topic=self.settings.input_topic,
            output_topic=self.settings.output_topic,
        )

    async def stop(self) -> None:
        self.running = False
        await self._export_all()
        if self.consumer is not None:
            await self.consumer.stop()
        if self.producer is not None:
            await self.producer.stop()
        logger.info(
            "feature extractor stopped",
            packets_processed=self.packets_processed,
            flows_exported=self.flows_exported,
            publish_errors=self.publish_errors,
        )

    # -- main loop ---------------------------------------------------------
    async def run(self) -> None:
        self.running = True
        loop = asyncio.get_running_loop()
        last_flush = loop.time()
        last_cleanup = last_flush

        assert self.consumer is not None
        async for msg in self.consumer:
            if not self.running:
                break

            self._process_packet(msg.value)
            self.packets_processed += 1

            now = loop.time()
            if now - last_flush >= self.settings.flush_interval:
                await self._export_expired(now)
                last_flush = now

            if now - last_cleanup >= self.settings.cleanup_interval:
                await self._cleanup(now)
                last_cleanup = now

    # -- packet handling ---------------------------------------------------
    def _process_packet(self, pkt: RawPacket) -> None:
        key = FlowKey.from_packet(pkt)
        state = self.flows.get(key)

        if state is None:
            if len(self.flows) >= self.settings.max_flows:
                self._evict_oldest()
            state = FlowState(key=key, start_time=pkt.timestamp, last_time=pkt.timestamp)
            self.flows[key] = state

        state.last_time = max(state.last_time, pkt.timestamp)

        if state.is_forward(pkt):
            state.packets_fwd += 1
            state.bytes_fwd += pkt.length
        else:
            state.packets_rev += 1
            state.bytes_rev += pkt.length

        state.pkt_sizes.append(pkt.length)

        if not state.payload_sample and pkt.payload:
            state.payload_sample = pkt.payload[:256]

        self._parse_app_layer(state, pkt)

    def _parse_app_layer(self, state: FlowState, pkt: RawPacket) -> None:
        """Best-effort application layer metadata extraction."""
        payload = pkt.payload
        if not payload:
            return

        is_dns = pkt.src_port == 53 or pkt.dst_port == 53
        if is_dns and len(payload) >= 12 and payload[2:4] == b"\x01\x00":
            state.dns_queries.append(payload[:64])

        if pkt.dst_port in (80, 8080, 8000) and payload[:4] in (b"GET ", b"POST"):
            marker = payload.find(b"Host: ")
            if marker != -1:
                end = payload.find(b"\r\n", marker)
                if end != -1:
                    state.http_hosts.append(payload[marker + 6 : end].decode(errors="ignore"))

        if pkt.dst_port == 443 and payload[:1] == b"\x16":
            state.tls_sni.append("handshake")

    # -- export ------------------------------------------------------------
    async def _export_expired(self, now: float) -> None:
        expired = [
            k for k, v in self.flows.items() if v.is_expired(now, self.settings.flow_timeout)
        ]
        for key in expired:
            await self._publish(self.flows.pop(key))

    async def _export_all(self) -> None:
        for key in list(self.flows):
            await self._publish(self.flows.pop(key))

    async def _cleanup(self, now: float) -> None:
        """Force-expire very old flows so memory stays bounded."""
        hard = self.settings.flow_timeout * self.settings.hard_expiry_multiplier
        stale = [k for k, v in self.flows.items() if v.is_expired(now, hard)]
        for key in stale:
            await self._publish(self.flows.pop(key))
        if stale:
            logger.warning("force-expired stale flows", count=len(stale))

    def _evict_oldest(self) -> None:
        if not self.flows:
            return
        oldest = min(self.flows.items(), key=lambda kv: kv[1].last_time)
        self.flows.pop(oldest[0])
        self.packets_skipped += 1

    async def _publish(self, state: FlowState) -> None:
        if self.producer is None:
            return
        features = summarize_flow(state, pcap_source="")
        try:
            await self.producer.send_and_wait(self.settings.output_topic, features)
            self.flows_exported += 1
        except Exception:  # noqa: BLE001 - one bad publish must not kill the loop
            self.publish_errors += 1
            logger.exception("failed to publish flow", flow_id=features.flow_id)


async def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    settings = Settings()
    extractor = FeatureExtractor(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(extractor.stop()))

    await extractor.start()
    try:
        await extractor.run()
    finally:
        await extractor.stop()


if __name__ == "__main__":
    asyncio.run(main())
