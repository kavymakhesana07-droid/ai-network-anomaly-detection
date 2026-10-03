"""SIEM Output Service - Elasticsearch/OpenSearch sink for enriched alerts.

Consumes alerts.enriched and indexes them into Elasticsearch/OpenSearch
using ECS (Elastic Common Schema) format.
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import structlog
from aiokafka import AIOKafkaConsumer
from elasticsearch import AsyncElasticsearch
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from output.models import (
    create_siem_event,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    alerts_topic: str = Field(default="alerts.enriched", alias="ALERTS_TOPIC")
    consumer_group: str = Field(default="siem-output", alias="CONSUMER_GROUP")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Elasticsearch
    elasticsearch_url: str = Field(default="http://elasticsearch:9200", alias="ELASTICSEARCH_URL")
    elasticsearch_index: str = Field(default="network-alerts", alias="ELASTICSEARCH_INDEX")
    elasticsearch_username: str | None = Field(default=None, alias="ELASTICSEARCH_USERNAME")
    elasticsearch_password: str | None = Field(default=None, alias="ELASTICSEARCH_PASSWORD")
    elasticsearch_api_key: str | None = Field(default=None, alias="ELASTICSEARCH_API_KEY")
    elasticsearch_verify_certs: bool = Field(default=False, alias="ELASTICSEARCH_VERIFY_CERTS")
    elasticsearch_ca_certs: str | None = Field(default=None, alias="ELASTICSEARCH_CA_CERTS")

    # Index settings
    index_template_name: str = Field(default="network-alerts-template", alias="INDEX_TEMPLATE_NAME")
    ilm_policy_name: str = Field(default="network-alerts-ilm", alias="ILM_POLICY_NAME")
    rollover_alias: str = Field(default="network-alerts", alias="ROLLOVER_ALIAS")

    # Batching
    batch_size: int = Field(default=100, alias="BATCH_SIZE")
    flush_interval_seconds: int = Field(default=10, alias="FLUSH_INTERVAL_SECONDS")
    max_retries: int = Field(default=3, alias="MAX_RETRIES")
    retry_backoff_seconds: float = Field(default=1.0, alias="RETRY_BACKOFF_SECONDS")

    # Output format
    output_format: str = Field(default="ecs", alias="OUTPUT_FORMAT")

    # Metrics
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")


class SIEMOutputService:
    """SIEM Output Service - indexes alerts to Elasticsearch/OpenSearch."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.consumer: Any = None
        self.es_client: Any = None
        self.running = False

        # Batching
        self.batch: list[dict] = []
        self.last_flush = time.time()

        # Metrics
        self.events_received: int = 0
        self.events_indexed: int = 0
        self.events_failed: int = 0
        self.batches_flushed: int = 0

    async def start(self) -> None:
        """Initialize Kafka consumer and Elasticsearch client."""
        # Kafka consumer
        self.consumer = AIOKafkaConsumer(
            self.settings.alerts_topic,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id="siem-output-consumer",
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=self.settings.kafka_batch_size,
            value_deserializer=lambda m: json.loads(m.decode()),
        )
        await self.consumer.start()
        logger.info("SIEM Output Kafka consumer started", topic=self.settings.alerts_topic)

        # Elasticsearch client
        self.es_client = await self._create_es_client()

        # Setup index template and ILM policy
        await self._setup_index_template()
        await self._setup_ilm_policy()

        logger.info(
            "SIEM Output service initialized",
            es_url=self.settings.elasticsearch_url,
            index=self.settings.elasticsearch_index,
        )

    async def stop(self) -> None:
        """Graceful shutdown - flush remaining batch."""
        self.running = False

        # Flush remaining batch
        if self.batch:
            await self._flush_batch()

        if self.consumer:
            await self.consumer.stop()
        if self.es_client:
            await self.es_client.close()

        logger.info(
            "SIEM Output service stopped",
            received=self.events_received,
            indexed=self.events_indexed,
            failed=self.events_failed,
            batches=self.batches_flushed,
        )

    async def _create_es_client(self) -> Any:
        """Create Elasticsearch client with auth."""

        kwargs: dict[str, Any] = {
            "hosts": [self.settings.elasticsearch_url],
            "verify_certs": self.settings.elasticsearch_verify_certs,
            "request_timeout": 30,
            "max_retries": self.settings.max_retries,
            "retry_on_timeout": True,
        }

        if self.settings.elasticsearch_ca_certs:
            kwargs["ca_certs"] = self.settings.elasticsearch_ca_certs

        if self.settings.elasticsearch_api_key:
            kwargs["api_key"] = self.settings.elasticsearch_api_key
        elif self.settings.elasticsearch_username and self.settings.elasticsearch_password:
            kwargs["basic_auth"] = (
                self.settings.elasticsearch_username,
                self.settings.elasticsearch_password,
            )

        client = AsyncElasticsearch(**kwargs)

        # Test connection
        await client.ping()
        logger.info("Elasticsearch client connected", url=self.settings.elasticsearch_url)
        return client

    async def _setup_index_template(self) -> None:
        """Create index template for network alerts."""
        template = {
            "index_patterns": [f"{self.settings.elasticsearch_index}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "10s",
                    "index.lifecycle.name": self.settings.ilm_policy_name,
                    "index.lifecycle.rollover_alias": self.settings.rollover_alias,
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event": {
                            "properties": {
                                "kind": {"type": "keyword"},
                                "category": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "outcome": {"type": "keyword"},
                                "severity": {"type": "keyword"},
                                "risk_score": {"type": "integer"},
                                "module": {"type": "keyword"},
                                "dataset": {"type": "keyword"},
                            }
                        },
                        "source": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "integer"},
                                "geo": {
                                    "properties": {
                                        "country_iso_code": {"type": "keyword"},
                                        "city_name": {"type": "keyword"},
                                        "location": {"type": "geo_point"},
                                    }
                                },
                                "as": {
                                    "properties": {
                                        "number": {"type": "long"},
                                        "organization": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "integer"},
                                "geo": {
                                    "properties": {
                                        "country_iso_code": {"type": "keyword"},
                                        "city_name": {"type": "keyword"},
                                        "location": {"type": "geo_point"},
                                    }
                                },
                                "as": {
                                    "properties": {
                                        "number": {"type": "long"},
                                        "organization": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "network": {
                            "properties": {
                                "protocol": {"type": "keyword"},
                                "transport": {"type": "keyword"},
                                "direction": {"type": "keyword"},
                            }
                        },
                        "rule": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "description": {"type": "text"},
                                "ruleset": {"type": "keyword"},
                            }
                        },
                        "threat": {
                            "properties": {
                                "indicator": {
                                    "properties": {
                                        "ip": {"type": "ip"},
                                    }
                                },
                                "enrichment": {"type": "object"},
                            }
                        },
                        "observer": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "vendor": {"type": "keyword"},
                                "version": {"type": "keyword"},
                            }
                        },
                        "alert": {
                            "properties": {
                                "type": {"type": "keyword"},
                                "score": {"type": "float"},
                                "model_version": {"type": "keyword"},
                                "inference_time_ms": {"type": "float"},
                            }
                        },
                        "enrichment": {
                            "properties": {
                                "src_ip": {"type": "object"},
                                "dst_ip": {"type": "object"},
                                "stix": {"type": "object"},
                            }
                        },
                        "correlation": {
                            "properties": {
                                "correlated_alerts": {"type": "keyword"},
                                "correlation_score": {"type": "float"},
                                "group_id": {"type": "keyword"},
                            }
                        },
                    }
                },
            },
        }
        try:
            exists = await self.es_client.indices.exists_index_template(
                name=self.settings.index_template_name
            )
            if not exists:
                await self.es_client.indices.put_index_template(
                    name=self.settings.index_template_name,
                    body=template,
                )
                logger.info("Index template created", name=self.settings.index_template_name)
            else:
                logger.info("Index template already exists", name=self.settings.index_template_name)
        except Exception as exc:
            logger.warning("Failed to create index template", error=str(exc))

    async def _setup_ilm_policy(self) -> None:
        """Create ILM policy for index lifecycle management."""
        policy = {
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "rollover": {
                                "max_size": "50GB",
                                "max_age": "1d",
                            },
                            "set_priority": {"priority": 100},
                        },
                    },
                    "warm": {
                        "min_age": "7d",
                        "actions": {
                            "set_priority": {"priority": 50},
                            "readonly": {},
                            "forcemerge": {"max_num_segments": 1},
                        },
                    },
                    "cold": {
                        "min_age": "30d",
                        "actions": {
                            "set_priority": {"priority": 0},
                            "readonly": {},
                        },
                    },
                    "delete": {
                        "min_age": "90d",
                        "actions": {
                            "delete": {},
                        },
                    },
                }
            }
        }
        try:
            exists = await self.es_client.ilm.get_lifecycle(name=self.settings.ilm_policy_name)
            if not exists:
                await self.es_client.ilm.put_lifecycle(
                    name=self.settings.ilm_policy_name,
                    body=policy,
                )
                logger.info("ILM policy created", name=self.settings.ilm_policy_name)
            else:
                logger.info("ILM policy already exists", name=self.settings.ilm_policy_name)
        except Exception as exc:
            logger.warning("Failed to create ILM policy", error=str(exc))

    def _create_siem_event(self, raw_alert: dict[str, Any]) -> dict:
        """Convert raw alert to ECS-format document."""
        siem_event = create_siem_event(raw_alert)
        return asdict(siem_event)

    async def _flush_batch(self) -> None:
        """Flush accumulated batch to Elasticsearch using bulk API."""
        if not self.batch:
            return

        actions = []
        for doc in self.batch:
            # Use rollover alias for index name
            actions.append({
                "index": {
                    "_index": self.settings.rollover_alias,
                }
            })
            actions.append(doc)

        try:
            from elasticsearch.helpers import async_bulk

            success, failed = await async_bulk(
                self.es_client,
                actions,
                stats_only=False,
                raise_on_error=False,
                max_retries=self.settings.max_retries,
            )

            self.events_indexed += success
            self.events_failed += len(failed) if failed else 0

            if failed:
                for item in failed:
                    logger.warning("Bulk index failed", error=item.get("index", {}).get("error"))

            self.batches_flushed += 1
            logger.debug("Batch flushed", success=success, failed=len(failed) if failed else 0)

        except Exception as exc:
            self.events_failed += len(self.batch)
            logger.exception("Bulk index failed", error=str(exc))
        finally:
            self.batch.clear()
            self.last_flush = time.time()

    async def process_message(self, msg: dict[str, Any]) -> None:
        """Process a single alert message."""
        self.events_received += 1

        try:
            doc = self._create_siem_event(msg)
            self.batch.append(doc)
        except Exception as exc:
            self.events_failed += 1
            logger.warning("Failed to create SIEM event", error=str(exc))
            return

        # Check if we should flush
        now = time.time()
        if (
            len(self.batch) >= self.settings.batch_size
            or now - self.last_flush >= self.settings.flush_interval_seconds
        ):
            await self._flush_batch()

    async def run(self) -> None:
        """Main processing loop."""
        self.running = True
        logger.info("SIEM Output service started")

        try:
            async for msg in self.consumer:
                if not self.running:
                    break
                await self.process_message(msg.value)

                # Periodic metrics
                if self.events_received % 1000 == 0:
                    logger.info(
                        "SIEM Output stats",
                        received=self.events_received,
                        indexed=self.events_indexed,
                        failed=self.events_failed,
                        batches=self.batches_flushed,
                        batch_size=len(self.batch),
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
    service = SIEMOutputService(settings)

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
