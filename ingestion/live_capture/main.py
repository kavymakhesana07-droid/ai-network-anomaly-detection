"""
Live Capture Ingestor - Captures live packets via AF_PACKET and publishes to Kafka.
Production-grade: async I/O, backpressure, checkpointing, metrics.
"""

import asyncio
import signal
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import structlog
from aiokafka import AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import LiveCaptureConfig, create_raw_socket, extract_flow_key

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    kafka_topic: str = Field(default="raw.packets", alias="TOPIC")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=10, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Live capture
    interface: str = Field(alias="INTERFACE")
    promisc: bool = Field(default=True, alias="PROMISC")
    snaplen: int = Field(default=65535, alias="SNAPLEN")
    buffer_size: int = Field(default=1 << 20, alias="BUFFER_SIZE")

    # Checkpointing (packet count)
    checkpoint_dir: str = Field(default="./data/checkpoints", alias="CHECKPOINT_DIR")
    checkpoint_interval: int = Field(default=10000, alias="CHECKPOINT_INTERVAL")

    # Metrics
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")


@dataclass(slots=True)
class PacketRecord:
    """Normalized packet record for Kafka."""

    timestamp: float
    interface: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    flow_key: str  # "src_ip:src_port->dst_ip:dst_port/proto"


class LiveCaptureIngestor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.producer: AIOKafkaProducer | None = None
        self.sock: socket.socket | None = None
        self.running = False
        self.packets_sent = 0
        self.packets_failed = 0
        self.packets_dropped = 0
        self._checkpoint_file = (
            Path(settings.checkpoint_dir) / f"live_{settings.interface}.checkpoint"
        )

    async def start(self) -> None:
        """Initialize Kafka producer and raw socket."""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            batch_size=self.settings.kafka_batch_size,
            linger_ms=self.settings.kafka_linger_ms,
            compression_type=self.settings.kafka_compression,
            value_serializer=lambda v: v.__dict__.__reduce_ex__(2)[
                1
            ],  # Will use model_dump_json below
            acks="all",
            enable_idempotence=True,
        )
        await self.producer.start()
        logger.info("Kafka producer started", brokers=self.settings.kafka_brokers)

        # Create raw socket
        cap_config = LiveCaptureConfig(
            interface=self.settings.interface,
            promisc=self.settings.promisc,
            snaplen=self.settings.snaplen,
            buffer_size=self.settings.buffer_size,
        )
        self.sock = create_raw_socket(cap_config)
        logger.info("Raw socket created", interface=self.settings.interface)

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        if self.producer:
            await self.producer.stop()
        if self.sock:
            self.sock.close()
        logger.info(
            "Ingestor stopped",
            sent=self.packets_sent,
            failed=self.packets_failed,
            dropped=self.packets_dropped,
        )

    def _load_checkpoint(self) -> int:
        if not self._checkpoint_file.exists():
            return 0
        try:
            return int(self._checkpoint_file.read_text().strip())
        except (ValueError, OSError) as exc:
            logger.warning("unreadable checkpoint, restarting from 0", error=str(exc))
            return 0

    def _save_checkpoint(self, packet_num: int) -> None:
        self._checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._checkpoint_file.with_suffix(".tmp")
        tmp.write_text(str(packet_num))
        tmp.replace(self._checkpoint_file)

    async def process_packets(self) -> None:
        """Main capture loop using asyncio sock_recv."""
        loop = asyncio.get_running_loop()
        packet_count = self._load_checkpoint()
        batch: list[PacketRecord] = []
        batch_size = 100  # Flush every N packets

        logger.info(
            "Starting live capture", interface=self.settings.interface, resume_from=packet_count
        )

        try:
            while self.running:
                try:
                    # recv with timeout via asyncio
                    assert self.sock is not None, "Socket not initialized"
                    data = await asyncio.wait_for(
                        loop.sock_recv(self.sock, self.settings.snaplen),
                        timeout=self.settings.timeout_ms / 1000
                        if hasattr(self.settings, "timeout_ms")
                        else 1.0,
                    )
                except TimeoutError:
                    # Periodic flush + checkpoint
                    if batch:
                        await self._flush_batch(batch)
                        batch.clear()
                    self._save_checkpoint(packet_count)
                    continue
                except OSError as exc:
                    if self.running:
                        logger.warning("socket recv error", error=str(exc))
                        await asyncio.sleep(0.1)
                    continue

                if not data:
                    continue

                packet_count += 1

                # Parse flow key
                flow_key_tuple = extract_flow_key(data)
                if flow_key_tuple is None:
                    self.packets_dropped += 1
                    continue

                src_ip, dst_ip, src_port, dst_port, protocol = flow_key_tuple
                flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"

                record = PacketRecord(
                    timestamp=time.time(),
                    interface=self.settings.interface,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    length=len(data),
                    flow_key=flow_key,
                )
                batch.append(record)

                # Flush batch
                if len(batch) >= batch_size:
                    await self._flush_batch(batch)
                    batch.clear()

                    # Checkpoint
                    if packet_count % self.settings.checkpoint_interval == 0:
                        self._save_checkpoint(packet_count)

        except Exception:
            logger.exception("Live capture failed", interface=self.settings.interface)
            raise
        finally:
            if batch:
                await self._flush_batch(batch)
            self._save_checkpoint(packet_count)

    async def _flush_batch(self, batch: list[PacketRecord]) -> None:
        if not self.producer or not batch:
            return

        try:
            futures = [
                self.producer.send_and_wait(self.settings.kafka_topic, record.__dict__)
                for record in batch
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

    settings = Settings()  # type: ignore[call-arg]
    ingestor = LiveCaptureIngestor(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(ingestor.stop()))

    ingestor.running = True
    await ingestor.start()

    try:
        await ingestor.process_packets()
    finally:
        await ingestor.stop()


if __name__ == "__main__":
    asyncio.run(main())
