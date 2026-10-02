"""Alerting & Correlation Service - Deduplication, enrichment, routing.

Consumes alerts from all detectors (raw, deep, xgboost), deduplicates,
enriches with threat intel, correlates related alerts, and routes to
severity-based output topics.
"""

from __future__ import annotations

import asyncio
import json
import signal
import time
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from typing import Any

import redis.asyncio as redis
import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    AlertingConfig,
    AlertSeverity,
    AlertStatus,
    CorrelationGroup,
    EnrichedAlert,
    calculate_correlation_score,
    create_stix_indicator,
    enrich_ip_whois,
    enrich_ip_whois_domain,
    generate_correlation_id,
    generate_dedup_key,
    is_dedup_expired,
    merge_alerts,
    route_alert,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    input_topics: str = Field(default="alerts.raw,alerts.deep", alias="INPUT_TOPICS")
    output_topic_base: str = Field(default="alerts", alias="OUTPUT_TOPIC_BASE")
    consumer_group: str = Field(default="alerting", alias="CONSUMER_GROUP")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Deduplication
    dedup_window_seconds: int = Field(default=300, alias="DEDUP_WINDOW_SECONDS")
    dedup_key_fields: str = Field(
        default="alert_type,flow_key,src_ip,dst_ip,src_port,dst_port",
        alias="DEDUP_KEY_FIELDS",
    )

    # Correlation
    correlation_window_seconds: int = Field(default=3600, alias="CORRELATION_WINDOW_SECONDS")
    min_correlation_score: float = Field(default=0.7, alias="MIN_CORRELATION_SCORE")

    # Enrichment
    enrichment_timeout_seconds: int = Field(default=5, alias="ENRICHMENT_TIMEOUT_SECONDS")
    enable_ipwhois: bool = Field(default=True, alias="ENABLE_IPWHOIS")
    enable_whois: bool = Field(default=True, alias="ENABLE_WHOIS")
    enable_stix: bool = Field(default=True, alias="ENABLE_STIX")
    enable_misp: bool = Field(default=False, alias="ENABLE_MISP")

    # Routing
    default_severity: str = Field(default="warning", alias="DEFAULT_SEVERITY")
    severity_mapping: str = Field(
        default='{"fast_path":"warning","deep_path":"error","xgboost_supervised":"critical"}',
        alias="SEVERITY_MAPPING",
    )

    # Redis
    redis_url: str = Field(default="redis://redis:6379", alias="REDIS_URL")
    dedup_ttl_seconds: int = Field(default=86400, alias="DEDUP_TTL_SECONDS")

    # Metrics
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")


@dataclass(slots=True)
class AlertingService:
    settings: Settings
    consumer: Any = None
    producer: Any = None
    redis_client: Any = None
    running: bool = False

    # Config parsed from settings
    config: AlertingConfig = field(default_factory=AlertingConfig)

    # In-memory state (backed by Redis for dedup)
    dedup_cache: dict[str, Any] = field(default_factory=dict)  # key -> EnrichedAlert
    correlation_groups: dict[str, Any] = field(default_factory=dict)  # group_id -> CorrelationGroup

    # Metrics
    alerts_received: int = 0
    alerts_deduped: int = 0
    alerts_enriched: int = 0
    alerts_correlated: int = 0
    alerts_routed: int = 0
    enrichment_failures: int = 0

    def __post_init__(self) -> None:
        self._parse_config()

    def _parse_config(self) -> None:
        """Parse settings into AlertingConfig."""
        dedup_fields = [f.strip() for f in self.settings.dedup_key_fields.split(",")]

        # Parse severity mapping from settings, fall back to default on error
        with suppress(json.JSONDecodeError):
            json.loads(self.settings.severity_mapping)

        output_topics: dict[Any, str] = {}
        for sev in AlertSeverity:
            output_topics[sev] = f"{self.settings.output_topic_base}.{sev.value}"

        self.config = AlertingConfig(
            dedup_window_seconds=self.settings.dedup_window_seconds,
            dedup_key_fields=[f.strip() for f in dedup_fields],
            correlation_window_seconds=self.settings.correlation_window_seconds,
            min_correlation_score=self.settings.min_correlation_score,
            enrichment_timeout_seconds=self.settings.enrichment_timeout_seconds,
            enable_ipwhois=self.settings.enable_ipwhois,
            enable_whois=self.settings.enable_whois,
            enable_stix=self.settings.enable_stix,
            enable_misp=self.settings.enable_misp,
            default_severity=AlertSeverity(self.settings.default_severity),
            severity_mapping={
                k: AlertSeverity(v) for k, v in json.loads(self.settings.severity_mapping).items()
            },
            output_topics={
                AlertSeverity(k): v
                for k, v in {
                    "debug": "alerts.debug",
                    "info": "alerts.info",
                    "notice": "alerts.notice",
                    "warning": "alerts.warning",
                    "error": "alerts.error",
                    "critical": "alerts.critical",
                    "alert": "alerts.alert",
                    "emergency": "alerts.emergency",
                }.items()
            },
            redis_url=self.settings.redis_url,
            dedup_ttl_seconds=self.settings.dedup_ttl_seconds,
        )

    async def start(self) -> None:
        """Initialize Kafka, Redis, and config."""
        # Parse input topics
        topics = [t.strip() for t in self.settings.input_topics.split(",")]

        # Kafka consumer
        self.consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id=self.settings.consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=self.settings.kafka_batch_size,
            value_deserializer=lambda m: json.loads(m.decode()),
        )
        await self.consumer.start()
        logger.info("Kafka consumer started", topics=topics)

        # Kafka producer
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            batch_size=self.settings.kafka_batch_size,
            linger_ms=self.settings.kafka_linger_ms,
            compression_type=self.settings.kafka_compression,
            value_serializer=lambda v: json.dumps(v).encode(),
            acks="all",
            enable_idempotence=True,
        )
        await self.producer.start()
        logger.info("Kafka producer started", brokers=self.settings.kafka_brokers)

        # Redis
        self.redis_client = redis.from_url(
            self.settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Redis connected", url=self.settings.redis_url)

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        if self.redis_client:
            await self.redis_client.close()
        logger.info(
            "Alerting service stopped",
            received=self.alerts_received,
            deduped=self.alerts_deduped,
            enriched=self.alerts_enriched,
            correlated=self.alerts_correlated,
            routed=self.alerts_routed,
        )

    async def enrich_alert(self, alert: dict[str, Any]) -> EnrichedAlert:
        """Enrich a raw alert with threat intelligence."""
        # Determine base severity from alert_type
        alert_type = alert.get("alert_type", "unknown")
        severity = AlertSeverity.WARNING
        for key, sev in self.config.severity_mapping.items():
            if key in alert_type:
                severity = sev
                break

        # Build enriched alert
        enriched = EnrichedAlert(
            alert_type=alert.get("alert_type", "unknown"),
            flow_key=alert.get("flow_key", ""),
            timestamp=alert.get("timestamp", time.time()),
            is_anomaly=alert.get("is_anomaly", False),
            src_ip=alert.get("src_ip"),
            dst_ip=alert.get("dst_ip"),
            src_port=alert.get("src_port"),
            dst_port=alert.get("dst_port"),
            protocol=alert.get("protocol"),
            anomaly_score=alert.get("anomaly_score"),
            reconstruction_error=alert.get("reconstruction_error"),
            anomaly_probability=alert.get("anomaly_probability"),
            model_version=alert.get("model_version"),
            inference_time_ms=alert.get("inference_time_ms"),
            severity=severity,
            status=AlertStatus.NEW,
            dedup_key="",  # will be set after
            first_seen=time.time(),
            last_seen=time.time(),
        )

        # Generate dedup key
        enriched.dedup_key = generate_dedup_key(alert, self.config.dedup_key_fields)

        # Determine output topic
        enriched.output_topic = route_alert(enriched, self.config)

        # Async enrichment tasks
        enrichment_tasks = []
        if self.config.enable_ipwhois and enriched.src_ip:
            enrichment_tasks.append(self._enrich_ip(enriched.src_ip, "src"))
        if self.config.enable_ipwhois and enriched.dst_ip:
            enrichment_tasks.append(self._enrich_ip(enriched.dst_ip, "dst"))
        if self.config.enable_whois and enriched.src_ip:
            enrichment_tasks.append(self._enrich_whois(enriched.src_ip, "src"))
        if self.config.enable_whois and enriched.dst_ip:
            enrichment_tasks.append(self._enrich_whois(enriched.dst_ip, "dst"))

        if enrichment_tasks:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*enrichment_tasks, return_exceptions=True),
                    timeout=self.config.enrichment_timeout_seconds,
                )
                for result in results:
                    if isinstance(result, tuple) and len(result) == 2:
                        field_name, data = result
                        setattr(enriched, field_name, data)
                    elif isinstance(result, Exception):
                        logger.warning("Enrichment task failed", error=str(result))
                        self.enrichment_failures += 1
            except TimeoutError:
                logger.warning("Enrichment timeout")
                self.enrichment_failures += 1

        # STIX indicator
        if self.config.enable_stix:
            stix = create_stix_indicator(enriched)
            if stix:
                enriched.stix_indicators.append(stix)

        return enriched

    async def _enrich_ip(self, ip: str, field: str) -> tuple[str, dict[str, Any] | None] | None:
        """Enrich a single IP with WHOIS data."""
        try:
            # In real implementation, use ipwhois library
            result = enrich_ip_whois(ip)
        except Exception as exc:
            logger.warning("IP enrichment failed", ip=ip, error=str(exc))
            return None
        else:
            return f"{field}_ip_enrichment", result

    async def _enrich_whois(self, ip: str, field: str) -> tuple[str, dict[str, Any] | None] | None:
        """Enrich a single IP with domain WHOIS data."""
        try:
            result = enrich_ip_whois_domain(ip)
        except Exception as exc:
            logger.warning("WHOIS enrichment failed", ip=ip, error=str(exc))
            return None
        else:
            return f"{field}_ip_enrichment", result

    async def deduplicate(self, alert: EnrichedAlert) -> EnrichedAlert | None:
        """Deduplicate an alert using Redis-backed cache."""
        dedup_key = alert.dedup_key

        # Check Redis first
        if self.redis_client:
            cached = await self.redis_client.get(f"dedup:{dedup_key}")
            if cached:
                try:
                    existing_data = json.loads(cached)
                    existing = EnrichedAlert(**existing_data)
                    if not is_dedup_expired(existing, self.config.dedup_window_seconds):
                        # Merge and update
                        merged = merge_alerts(existing, alert)
                        await self.redis_client.setex(
                            f"dedup:{dedup_key}",
                            self.config.dedup_ttl_seconds,
                            json.dumps(asdict(merged), default=str),
                        )
                        self.alerts_deduped += 1
                        return None  # Suppressed duplicate
                except (json.JSONDecodeError, TypeError):
                    pass

        # New alert - store in dedup cache
        if self.redis_client:
            await self.redis_client.setex(
                f"dedup:{alert.dedup_key}",
                self.config.dedup_ttl_seconds,
                json.dumps(asdict(alert), default=str),
            )
        return alert

    async def correlate(self, alert: EnrichedAlert) -> None:
        """Correlate alert with recent alerts."""
        group_id = generate_correlation_id([alert])

        # Check existing groups
        if group_id in self.correlation_groups:
            group = self.correlation_groups[group_id]
            group.alerts.append(alert)
            group.updated_at = time.time()

            # Recalculate correlation score
            if len(group.alerts) >= 2:
                scores = []
                for i, a1 in enumerate(group.alerts):
                    for _a2 in group.alerts[i + 1 :]:
                        scores.append(calculate_correlation_score(a1, alert))
                group.correlation_score = sum(scores) / len(scores) if scores else 0.0

            alert.correlated_alerts = [
                a.flow_key for a in group.alerts if a.flow_key != alert.flow_key
            ]
            alert.correlation_score = group.correlation_score
        else:
            # Create new group
            group = CorrelationGroup(
                group_id=group_id,
                alerts=[alert],
                created_at=time.time(),
                updated_at=time.time(),
                correlation_score=0.0,
            )
            self.correlation_groups[group_id] = group

        # Clean old groups
        now = time.time()
        expired = [
            gid
            for gid, g in self.correlation_groups.items()
            if now - g.updated_at > self.config.correlation_window_seconds
        ]
        for gid in expired:
            del self.correlation_groups[gid]

    async def route_alert(self, alert: EnrichedAlert) -> None:
        """Send enriched alert to appropriate output topic."""
        if self.producer is None:
            return
        try:
            payload = asdict(alert)
            # Convert non-serializable fields
            payload["severity"] = alert.severity.value
            payload["status"] = alert.status.value
            await self.producer.send_and_wait(alert.output_topic, payload)
            self.alerts_routed += 1
            if alert.is_anomaly:
                logger.warning(
                    "Alert routed",
                    flow_key=alert.flow_key,
                    topic=alert.output_topic,
                    severity=alert.severity.value,
                )
        except Exception as exc:
            logger.warning("Failed to route alert", error=str(exc))

    async def process_message(self, msg: dict[str, Any]) -> None:
        """Process a single alert message from Kafka."""
        self.alerts_received += 1

        # Enrich
        alert = await self.enrich_alert(msg)
        self.alerts_enriched += 1

        # Deduplicate
        deduped = await self.deduplicate(alert)
        if deduped is None:
            return  # Duplicate suppressed

        # Correlate
        await self.correlate(alert)
        self.alerts_correlated += 1

        # Route
        await self.route_alert(alert)

    async def run(self) -> None:
        """Main processing loop."""
        self.running = True
        logger.info("Alerting service started")

        if self.consumer is None:
            logger.error("Consumer not initialized")
            return

        try:
            async for msg in self.consumer:
                if not self.running:
                    break
                await self.process_message(msg.value)

                # Periodic metrics log
                if self.alerts_received % 1000 == 0:
                    logger.info(
                        "Alerting stats",
                        received=self.alerts_received,
                        deduped=self.alerts_deduped,
                        enriched=self.alerts_enriched,
                        correlated=self.alerts_correlated,
                        routed=self.alerts_routed,
                        enrich_failures=self.enrichment_failures,
                    )

        except Exception as exc:
            logger.exception("Processing loop error", error=str(exc))
            raise


async def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    settings = Settings()
    service = AlertingService(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(service.stop()))

    await service.start()
    try:
        await service.run()
    finally:
        await service.stop()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
