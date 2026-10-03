"""Integrations Service - Slack, PagerDuty, Mattermost, Webhooks.

Consumes alerts.enriched and forwards to configured ChatOps channels.
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import structlog
from aiokafka import AIOKafkaConsumer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from output.models import (
    format_alert_for_pagerduty,
    format_alert_for_slack,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    alerts_topic: str = Field(default="alerts.enriched", alias="ALERTS_TOPIC")
    consumer_group: str = Field(default="integrations", alias="CONSUMER_GROUP")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Slack
    slack_webhook_url: str | None = Field(default=None, alias="SLACK_WEBHOOK_URL")
    slack_channel: str = Field(default="#security-alerts", alias="SLACK_CHANNEL")
    slack_username: str = Field(default="anomaly-detector", alias="SLACK_USERNAME")
    slack_icon_emoji: str = Field(default=":warning:", alias="SLACK_ICON_EMOJI")

    # PagerDuty
    pagerduty_integration_key: str | None = Field(default=None, alias="PAGERDUTY_INTEGRATION_KEY")
    pagerduty_severity_mapping: str = Field(
        default='{"critical":"critical","error":"error","warning":"warning","info":"info"}',
        alias="PAGERDUTY_SEVERITY_MAPPING",
    )

    # Mattermost
    mattermost_webhook_url: str | None = Field(default=None, alias="MATTERMOST_WEBHOOK_URL")
    mattermost_channel: str = Field(default="security-alerts", alias="MATTERMOST_CHANNEL")

    # Generic webhook
    webhook_url: str | None = Field(default=None, alias="WEBHOOK_URL")
    webhook_headers: str = Field(default="{}", alias="WEBHOOK_HEADERS")

    # Filtering
    min_severity: str = Field(default="warning", alias="MIN_SEVERITY")
    enabled_channels: str = Field(default="slack", alias="ENABLED_CHANNELS")

    # HTTP client
    http_timeout_seconds: int = Field(default=10, alias="HTTP_TIMEOUT_SECONDS")
    max_retries: int = Field(default=3, alias="MAX_RETRIES")
    retry_backoff_seconds: float = Field(default=1.0, alias="RETRY_BACKOFF_SECONDS")


class IntegrationsService:
    """Integrations Service - forwards alerts to ChatOps channels."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.consumer: Any = None
        self.http_client: Any = None
        self.running = False

        # Parsed config
        self.enabled_channels: set[str] = set()
        self.min_severity_level: int = 0
        self.severity_order = {
            "debug": 0,
            "info": 1,
            "notice": 2,
            "warning": 3,
            "error": 4,
            "critical": 5,
            "alert": 6,
            "emergency": 7,
        }

        # Metrics
        self.alerts_received: int = 0
        self.alerts_sent: int = 0
        self.alerts_filtered: int = 0
        self.send_failures: int = 0

    async def start(self) -> None:
        """Initialize Kafka consumer and HTTP client."""
        # Parse config
        self.enabled_channels = {c.strip() for c in self.settings.enabled_channels.split(",")}
        self.min_severity_level = self.severity_order.get(self.settings.min_severity.lower(), 3)

        # Kafka consumer
        self.consumer = AIOKafkaConsumer(
            self.settings.alerts_topic,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id="integrations-consumer",
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=100,
            value_deserializer=lambda m: json.loads(m.decode()),
        )
        await self.consumer.start()
        logger.info("Integrations Kafka consumer started", topic=self.settings.alerts_topic)

        # HTTP client
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout_seconds),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        logger.info("Integrations HTTP client initialized", channels=list(self.enabled_channels))

    async def stop(self) -> None:
        """Graceful shutdown."""
        if self.consumer:
            await self.consumer.stop()
        if self.http_client:
            await self.http_client.aclose()
        logger.info(
            "Integrations service stopped",
            received=self.alerts_received,
            sent=self.alerts_sent,
            filtered=self.alerts_filtered,
            failures=self.send_failures,
        )

    def _should_alert(self, severity: str) -> bool:
        """Check if alert meets minimum severity threshold."""
        sev_level = self.severity_order.get(severity.lower(), 3)
        return sev_level >= self.min_severity_level

    async def _send_with_retry(
        self, url: str, payload: dict[str, Any], headers: dict[str, Any] | None = None
    ) -> bool:
        """Send HTTP request with retry logic."""
        for attempt in range(3):
            try:
                response = await self.http_client.post(url, json=payload, headers=headers)
                response.raise_for_status()
            except Exception as exc:
                if attempt == 2:
                    logger.warning("Webhook send failed after retries", url=url, error=str(exc))
                    return False
                await asyncio.sleep(1 * (attempt + 1))
            else:
                return True
        return False

    async def send_slack(self, alert: dict[str, Any]) -> bool:
        """Send alert to Slack webhook."""
        if not self.settings.slack_webhook_url:
            return False

        payload = format_alert_for_slack(alert)
        payload["channel"] = self.settings.slack_channel
        payload["username"] = self.settings.slack_username
        payload["icon_emoji"] = self.settings.slack_icon_emoji

        return await self._send_with_retry(self.settings.slack_webhook_url, payload)

    async def send_pagerduty(self, alert: dict[str, Any]) -> bool:
        """Send alert to PagerDuty Events API v2."""
        if not self.settings.pagerduty_integration_key:
            return False

        payload = format_alert_for_pagerduty(alert)
        payload["routing_key"] = self.settings.pagerduty_integration_key

        # Apply severity mapping
        try:
            mapping = json.loads(self.settings.pagerduty_severity_mapping)
            severity = alert.get("severity", "warning")
            if isinstance(severity, dict):
                severity = severity.get("value", "warning")
            payload["payload"]["severity"] = mapping.get(severity, severity)
        except json.JSONDecodeError:
            pass

        return await self._send_with_retry("https://events.pagerduty.com/v2/enqueue", payload)

    async def send_mattermost(self, alert: dict[str, Any]) -> bool:
        """Send alert to Mattermost webhook."""
        if not self.settings.mattermost_webhook_url:
            return False

        severity = alert.get("severity", "warning")
        if isinstance(severity, dict):
            severity = severity.get("value", "warning")

        color_map = {
            "critical": "#FF0000",
            "error": "#FF4500",
            "warning": "#FFA500",
            "info": "#00BFFF",
            "debug": "#808080",
        }

        payload = {
            "channel": self.settings.mattermost_channel,
            "username": "anomaly-detector",
            "icon_emoji": ":warning:",
            "attachments": [
                {
                    "color": color_map.get(severity, "#FFA500"),
                    "title": f"Network Anomaly: {alert.get('alert_type', 'Unknown')}",
                    "text": f"**Flow:** `{alert.get('flow_key', 'N/A')}`\n"
                    f"**Severity:** {severity}\n"
                    f"**Source:** {alert.get('src_ip', 'N/A')}:{alert.get('src_port', 'N/A')}\n"
                    f"**Destination:** {alert.get('dst_ip', 'N/A')}:{alert.get('dst_port', 'N/A')}\n"
                    f"**Score:** {alert.get('anomaly_score') or alert.get('reconstruction_error') or alert.get('anomaly_probability', 'N/A')}\n"
                    f"**Model:** {alert.get('model_version', 'N/A')}",
                    "ts": int(alert.get("timestamp", 0)),
                }
            ],
        }

        return await self._send_with_retry(self.settings.mattermost_webhook_url, payload)

    async def send_webhook(self, alert: dict[str, Any]) -> bool:
        """Send alert to generic webhook."""
        if not self.settings.webhook_url:
            return False

        try:
            headers = (
                json.loads(self.settings.webhook_headers) if self.settings.webhook_headers else {}
            )
        except json.JSONDecodeError:
            headers = {}

        payload = {
            "alert": alert,
            "timestamp": time.time(),
        }

        return await self._send_with_retry(self.settings.webhook_url, payload, headers)

    async def process_alert(self, alert: dict[str, Any]) -> None:
        """Process a single alert through all enabled channels."""
        self.alerts_received += 1

        # Filter by severity
        severity_raw = alert.get("severity", "warning")
        if isinstance(severity_raw, dict):
            severity = severity_raw.get("value", "warning")
        else:
            severity = str(severity_raw)

        if not self._should_alert(severity):
            self.alerts_filtered += 1
            return

        # Send to enabled channels
        tasks = []

        if "slack" in self.enabled_channels and self.settings.slack_webhook_url:
            tasks.append(self.send_slack(alert))

        if "pagerduty" in self.enabled_channels and self.settings.pagerduty_integration_key:
            tasks.append(self.send_pagerduty(alert))

        if "mattermost" in self.enabled_channels and self.settings.mattermost_webhook_url:
            tasks.append(self.send_mattermost(alert))

        if "webhook" in self.enabled_channels and self.settings.webhook_url:
            tasks.append(self.send_webhook(alert))

        if not tasks:
            logger.debug("No channels configured for alert")
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.send_failures += 1
                logger.warning("Channel send failed", error=str(result))
            elif result:
                self.alerts_sent += 1

    async def process_message(self, msg: Any) -> None:
        """Process a single alert message from Kafka."""
        await self.process_alert(msg.value)

    async def run(self) -> None:
        """Main processing loop."""
        logger.info("Integrations service started", channels=list(self.enabled_channels))

        try:
            async for msg in self.consumer:
                await self.process_alert(msg.value)

                if self.alerts_received % 100 == 0:
                    logger.info(
                        "Integrations stats",
                        received=self.alerts_received,
                        sent=self.alerts_sent,
                        filtered=self.alerts_filtered,
                        failures=self.send_failures,
                    )

        except Exception as exc:
            logger.exception("Processing loop error", error=str(exc))
            raise


async def main() -> None:
    import structlog

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    settings = Settings()
    service = IntegrationsService(settings)

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
    import json
    import time

    asyncio.run(main())
