"""
PCAP Ingestor - Reads PCAP files and publishes raw packets to Kafka.
Production-grade: batching, backpressure, checkpointing, metrics.
"""

import asyncio
import signal
from dataclasses import dataclass
from pathlib import Path

import structlog
from aiokafka import AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    kafka_topic: str = Field(default="raw.packets", alias="TOPIC")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=10, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # PCAP
    pcap_file: str = Field(alias="PCAP_FILE")
    batch_packets: int = Field(default=1000, alias="BATCH_PACKETS")
    replay_speed: float = Field(default=1.0, alias="REPLAY_SPEED")  # 1.0 = realtime

    # Checkpointing
    checkpoint_dir: str = Field(default="./data/checkpoints", alias="CHECKPOINT_DIR")
    checkpoint_interval: int = Field(default=10000, alias="CHECKPOINT_INTERVAL")

    # Metrics
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")


@dataclass
class PacketRecord:
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


class PCAPIngestor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.producer: AIOKafkaProducer | None = None
        self.running = False
        self.packets_sent = 0
        self.packets_failed = 0
        self._checkpoint_file = (
            Path(settings.checkpoint_dir) / f"{Path(settings.pcap_file).stem}.checkpoint"
        )

    async def start(self) -> None:
        """Initialize Kafka producer."""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            batch_size=self.settings.kafka_batch_size,
            linger_ms=self.settings.kafka_linger_ms,
            compression_type=self.settings.kafka_compression,
            value_serializer=lambda v: v.model_dump_json().encode(),
            acks="all",
            enable_idempotence=True,
        )
        await self.producer.start()
        logger.info("Kafka producer started", brokers=self.settings.kafka_brokers)

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        if self.producer:
            await self.producer.stop()
        logger.info("Ingestor stopped", sent=self.packets_sent, failed=self.packets_failed)

    def _load_checkpoint(self) -> int:
        """Load last processed packet number."""
        if not self._checkpoint_file.exists():
            return 0
        try:
            return int(self._checkpoint_file.read_text().strip())
        except (ValueError, OSError) as exc:
            logger.warning("unreadable checkpoint, restarting from 0", error=str(exc))
            return 0

    def _save_checkpoint(self, packet_num: int) -> None:
        """Save checkpoint atomically."""
        self._checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._checkpoint_file.with_suffix(".tmp")
        tmp.write_text(str(packet_num))
        tmp.replace(self._checkpoint_file)

    async def process_pcap(self) -> None:
        """Process PCAP file with Scapy."""
        from scapy.utils import PcapReader

        start_packet = self._load_checkpoint()
        logger.info(
            "Starting PCAP processing", file=self.settings.pcap_file, resume_from=start_packet
        )

        packet_count = 0
        batch = []

        try:
            with PcapReader(self.settings.pcap_file) as pcap:
                for pkt in pcap:
                    if not self.running:
                        break

                    packet_count += 1
                    if packet_count <= start_packet:
                        continue

                    # Parse packet
                    record = self._parse_packet(pkt, packet_count)
                    if record:
                        batch.append(record)

                    # Flush batch
                    if len(batch) >= self.settings.batch_packets:
                        await self._flush_batch(batch)
                        batch.clear()

                        # Checkpoint
                        if packet_count % self.settings.checkpoint_interval == 0:
                            self._save_checkpoint(packet_count)

                        # Rate limiting for replay
                        if self.settings.replay_speed > 0:
                            await asyncio.sleep(len(batch) / (self.settings.replay_speed * 1000))

        except Exception:
            logger.exception("PCAP processing failed", file=self.settings.pcap_file)
            raise
        finally:
            if batch:
                await self._flush_batch(batch)
            self._save_checkpoint(packet_count)

    def _parse_packet(self, pkt, packet_number: int) -> PacketRecord | None:
        """Extract flow features from packet."""
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        try:
            ip_layer = pkt.get(IP) or pkt.get(IPv6)
            if ip_layer is None:
                return None

            transport = pkt.get(TCP) or pkt.get(UDP)
            if transport is None:
                return None

            return PacketRecord(
                timestamp=float(pkt.time),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=int(transport.sport),
                dst_port=int(transport.dport),
                protocol=int(ip_layer.proto),
                length=len(pkt),
                payload=bytes(transport.payload)[:1024],
                pcap_file=self.settings.pcap_file,
                packet_number=packet_number,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            logger.debug("packet parse error", error=str(exc), packet=packet_number)
            return None

    async def _flush_batch(self, batch: list[PacketRecord]) -> None:
        """Send batch to Kafka."""
        if not self.producer or not batch:
            return

        try:
            futures = [
                self.producer.send_and_wait(self.settings.kafka_topic, record) for record in batch
            ]
            await asyncio.gather(*futures)
            self.packets_sent += len(batch)
            logger.debug("batch flushed", count=len(batch), total=self.packets_sent)
        except Exception:
            self.packets_failed += len(batch)
            logger.exception("batch send failed", count=len(batch))


async def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    # PCAP_FILE is supplied via the environment (Kubernetes ConfigMap / .env).
    # The type: ignore is required because pydantic-settings populates required
    # fields from env at runtime, which mypy cannot infer.
    settings = Settings()  # type: ignore[call-arg]
    ingestor = PCAPIngestor(settings)

    # Signal handling
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(ingestor.stop()))

    ingestor.running = True
    await ingestor.start()

    try:
        await ingestor.process_pcap()
    finally:
        await ingestor.stop()


if __name__ == "__main__":
    asyncio.run(main())
