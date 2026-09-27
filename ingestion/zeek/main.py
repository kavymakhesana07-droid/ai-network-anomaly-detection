"""
Zeek Log Ingestor - Tails Zeek log files and publishes records to Kafka.
Production-grade: file tailing, checkpointing, multi-format parsing, metrics.
"""

import asyncio
import gzip
import signal
import time
from dataclasses import dataclass
from pathlib import Path

import structlog
from aiokafka import AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from watchfiles import watch

from .models import (
    ZeekLogType,
    ZeekRecord,
    detect_log_type,
    normalize_record,
    parse_zeek_header,
    parse_zeek_line,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    kafka_topic: str = Field(default="raw.zeek", alias="TOPIC")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=10, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Zeek log directory
    log_dir: str = Field(default="./data/zeek_logs", alias="LOG_DIR")
    file_pattern: str = Field(default="*.log", alias="FILE_PATTERN")
    tail_files: bool = Field(default=True, alias="TAIL_FILES")
    poll_interval: float = Field(default=1.0, alias="POLL_INTERVAL")

    # Processing
    batch_size: int = Field(default=1000, alias="BATCH_SIZE")
    checkpoint_interval: int = Field(default=10000, alias="CHECKPOINT_INTERVAL")

    # Metrics
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")


@dataclass(slots=True)
class FileState:
    """Track position and parser state for a single log file."""

    path: Path
    file_handle: object | None = None
    position: int = 0
    fields: list[str] = None
    log_type: ZeekLogType = ZeekLogType.UNKNOWN
    lines_processed: int = 0
    is_gzipped: bool = False

    def __post_init__(self):
        self.is_gzipped = self.path.suffix == ".gz"


class ZeekIngestor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.producer: AIOKafkaProducer | None = None
        self.running = False
        self.file_states: dict[Path, FileState] = {}
        self.records_sent = 0
        self.records_failed = 0
        self.files_processed = 0
        self._checkpoint_dir = Path(settings.log_dir) / ".checkpoints"
        self._last_checkpoint_time = time.time()

    async def start(self) -> None:
        """Initialize Kafka producer and discover log files."""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            batch_size=self.settings.kafka_batch_size,
            linger_ms=self.settings.kafka_linger_ms,
            compression_type=self.settings.kafka_compression,
            value_serializer=lambda v: v.__dict__.__reduce_ex__(2)[1],
            acks="all",
            enable_idempotence=True,
        )
        await self.producer.start()
        logger.info("Kafka producer started", brokers=self.settings.kafka_brokers)

        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        await self._discover_files()

        if self.settings.tail_files:
            asyncio.create_task(self._watch_for_new_files())

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        for state in self.file_states.values():
            if state.file_handle:
                state.file_handle.close()
        if self.producer:
            await self.producer.stop()
        logger.info(
            "Ingestor stopped",
            records_sent=self.records_sent,
            records_failed=self.records_failed,
            files_processed=self.files_processed,
        )

    async def _discover_files(self) -> None:
        """Find and open all matching log files."""
        log_dir = Path(self.settings.log_dir)
        if not log_dir.exists():
            logger.warning("Log directory does not exist", path=str(log_dir))
            return

        pattern = self.settings.file_pattern
        for path in log_dir.glob(pattern):
            if path.is_file() and path not in self.file_states:
                await self._open_file(path)

    async def _watch_for_new_files(self) -> None:
        """Watch for new log files using watchfiles."""
        log_dir = Path(self.settings.log_dir)
        try:
            async for changes in watch(log_dir, recursive=False):
                for _change_type, path_str in changes:
                    path = Path(path_str)
                    if (
                        path.match(self.settings.file_pattern)
                        and path.is_file()
                        and path not in self.file_states
                    ):
                        await self._open_file(path)
                if not self.running:
                    break
        except Exception as exc:
            logger.warning("File watcher error", error=str(exc))

    async def _open_file(self, path: Path) -> None:
        """Open a log file, read header, and load checkpoint."""
        try:
            if path.suffix == ".gz":
                fh = gzip.open(path, "rt", encoding="utf-8", errors="replace")  # noqa: SIM115 - kept open for tailing
            else:
                fh = Path(path).open(encoding="utf-8", errors="replace")  # noqa: SIM115 - kept open for tailing

            # Read header
            first_line = fh.readline()
            if not first_line:
                fh.close()
                return

            fields = parse_zeek_header(first_line)
            if not fields:
                logger.warning("No fields header, skipping", file=str(path))
                fh.close()
                return

            log_type = detect_log_type(str(path), first_line)

            state = FileState(
                path=path,
                file_handle=fh,
                position=fh.tell(),
                fields=fields,
                log_type=log_type,
            )

            # Load checkpoint
            cp_file = self._checkpoint_dir / f"{path.name}.checkpoint"
            if cp_file.exists():
                try:
                    pos = int(cp_file.read_text().strip())
                    if pos < path.stat().st_size:
                        fh.seek(pos)
                        state.position = pos
                except (ValueError, OSError):
                    pass

            self.file_states[path] = state
            self.files_processed += 1
            logger.info("Opened log file", file=str(path), type=log_type.value, fields=len(fields))

        except Exception as exc:
            logger.warning("Failed to open log file", file=str(path), error=str(exc))

    async def process_logs(self) -> None:
        """Main processing loop - read new lines from all open files."""
        self.running = True
        batch = []

        while self.running:
            try:
                any_activity = False

                for path, state in list(self.file_states.items()):
                    if not state.file_handle:
                        continue

                    # Read available lines
                    for _ in range(100):  # Limit per iteration
                        line = state.file_handle.readline()
                        if not line:
                            break
                        any_activity = True

                        state.position = state.file_handle.tell()
                        state.lines_processed += 1

                        parsed = parse_zeek_line(line, state.fields)
                        if parsed is None:
                            continue

                        record = ZeekRecord(
                            log_type=state.log_type,
                            timestamp=0.0,  # Will be set by normalize
                            fields=parsed,
                            raw_line=line.rstrip("\n"),
                            file_path=str(path),
                            line_number=state.lines_processed,
                        )
                        record = normalize_record(record)
                        batch.append(record)

                        if len(batch) >= self.settings.batch_size:
                            await self._flush_batch(batch)
                            batch.clear()

                    # Checkpoint
                    if state.lines_processed % self.settings.checkpoint_interval == 0:
                        self._save_checkpoint(state)

                if not any_activity:
                    await asyncio.sleep(self.settings.poll_interval)

                # Periodic checkpoint
                if time.time() - self._last_checkpoint_time > 60:
                    for state in self.file_states.values():
                        self._save_checkpoint(state)
                    self._last_checkpoint_time = time.time()

            except Exception:
                logger.exception("Log processing error")
                await asyncio.sleep(1)

        # Final flush
        if batch:
            await self._flush_batch(batch)
        for state in self.file_states.values():
            self._save_checkpoint(state)

    def _save_checkpoint(self, state: FileState) -> None:
        try:
            cp_file = self._checkpoint_dir / f"{state.path.name}.checkpoint"
            cp_file.write_text(str(state.position))
        except Exception as exc:
            logger.warning("Checkpoint save failed", file=str(state.path), error=str(exc))

    async def _flush_batch(self, batch: list[ZeekRecord]) -> None:
        if not self.producer or not batch:
            return

        try:
            futures = [
                self.producer.send_and_wait(self.settings.kafka_topic, record.__dict__)
                for record in batch
            ]
            await asyncio.gather(*futures)
            self.records_sent += len(batch)
            logger.debug("batch flushed", count=len(batch), total=self.records_sent)
        except Exception:
            self.records_failed += len(batch)
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
    ingestor = ZeekIngestor(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(ingestor.stop()))

    await ingestor.start()

    try:
        await ingestor.process_logs()
    finally:
        await ingestor.stop()


if __name__ == "__main__":
    asyncio.run(main())
