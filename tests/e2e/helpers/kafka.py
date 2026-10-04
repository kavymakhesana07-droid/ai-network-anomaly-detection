"""Kafka test helper for E2E tests."""

from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic


class KafkaTestHelper:
    """Helper for managing Kafka topics and messages in E2E tests."""

    def __init__(
        self,
        bootstrap_servers: str,
        test_topics_prefix: str = "e2e-test-",
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.test_topics_prefix = test_topics_prefix
        self._admin_client: AIOKafkaAdminClient | None = None
        self._producer: AIOKafkaProducer | None = None
        self._consumers: list[AIOKafkaConsumer] = []
        self._created_topics: list[str] = []

    async def connect(self) -> None:
        """Initialize admin client and producer."""
        self._admin_client = AIOKafkaAdminClient(
            bootstrap_servers=self.bootstrap_servers,
            client_id="e2e-test-admin",
        )
        await self._admin_client.start()

        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: v if isinstance(v, bytes) else str(v).encode(),
            acks="all",
            enable_idempotence=True,
        )
        await self._producer.start()

    async def disconnect(self) -> None:
        """Clean up all resources."""
        for consumer in self._consumers:
            await consumer.stop()
        self._consumers.clear()

        if self._producer:
            await self._producer.stop()
            self._producer = None

        if self._admin_client:
            await self._admin_client.close()
            self._admin_client = None

    async def create_topic(
        self,
        name: str,
        partitions: int = 3,
        replication_factor: int = 1,
    ) -> str:
        """Create a test topic with unique name."""
        full_name = f"{self.test_topics_prefix}{name}"
        topic = NewTopic(
            name=full_name,
            num_partitions=partitions,
            replication_factor=replication_factor,
        )
        try:
            await self._admin_client.create_topics([topic])
            self._created_topics.append(full_name)
        except Exception as e:
            if "already exists" not in str(e).lower():
                raise
        return full_name

    async def delete_topic(self, name: str) -> None:
        """Delete a test topic."""
        full_name = f"{self.test_topics_prefix}{name}"
        from contextlib import suppress

        with suppress(Exception):
            await self._admin_client.delete_topics([full_name])
            if full_name in self._created_topics:
                self._created_topics.remove(full_name)

    async def cleanup_all(self) -> None:
        """Delete all created topics."""
        for topic in self._created_topics.copy():
            await self.delete_topic(topic.replace(self.test_topics_prefix, ""))

    async def produce(
        self,
        topic: str,
        value: Any,
        key: str | None = None,
        partition: int | None = None,
    ) -> None:
        """Produce a message to a topic."""
        full_topic = (
            f"{self.test_topics_prefix}{topic}"
            if not topic.startswith(self.test_topics_prefix)
            else topic
        )
        await self._producer.send_and_wait(
            topic=full_topic,
            value=value,
            key=key.encode() if key else None,
            partition=partition,
        )

    async def produce_batch(
        self,
        topic: str,
        messages: list[tuple[Any, str | None]],
    ) -> None:
        """Produce multiple messages to a topic."""
        full_topic = (
            f"{self.test_topics_prefix}{topic}"
            if not topic.startswith(self.test_topics_prefix)
            else topic
        )
        for value, key in messages:
            await self._producer.send(
                topic=full_topic,
                value=value if isinstance(value, bytes) else str(value).encode(),
                key=key.encode() if key else None,
            )
        await self._producer.flush()

    async def consume(
        self,
        topic: str,
        group_id: str,
        max_messages: int = 100,
        timeout_ms: int = 5000,
    ) -> list[dict]:
        """Consume messages from a topic."""
        full_topic = (
            f"{self.test_topics_prefix}{topic}"
            if not topic.startswith(self.test_topics_prefix)
            else topic
        )

        consumer = AIOKafkaConsumer(
            full_topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            value_deserializer=lambda m: m.decode() if m else None,
            consumer_timeout_ms=timeout_ms,
        )
        await consumer.start()
        self._consumers.append(consumer)

        messages = []
        try:
            async for msg in consumer:
                messages.append({
                    "topic": msg.topic,
                    "partition": msg.partition,
                    "offset": msg.offset,
                    "key": msg.key.decode() if msg.key else None,
                    "value": msg.value,
                    "timestamp": msg.timestamp,
                })
                if len(messages) >= max_messages:
                    break
        finally:
            await consumer.stop()
            if consumer in self._consumers:
                self._consumers.remove(consumer)

        return messages

    async def get_topic_metadata(self, topic: str) -> dict | None:
        """Get topic metadata."""
        try:
            await self._admin_client.describe_cluster()
            # Note: aiokafka doesn't have direct topic metadata access in all versions
            # This is a placeholder - actual implementation depends on aiokafka version
        except Exception:
            return None
        else:
            return {"topic": topic, "exists": True}
