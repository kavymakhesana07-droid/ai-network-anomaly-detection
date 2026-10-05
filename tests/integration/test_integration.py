"""Integration tests to verify service connectivity and basic functionality.

These tests require external services (Kafka/Redpanda, Redis, Elasticsearch).
They will be skipped if services are not available.
"""

import pytest

# Conditional imports for optional dependencies
try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.admin import KafkaAdminClient, NewTopic

    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    KafkaProducer = None
    KafkaConsumer = None
    KafkaAdminClient = None
    NewTopic = None

try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    from elasticsearch import AsyncElasticsearch

    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    AsyncElasticsearch = None


def is_kafka_available():
    """Check if Kafka/Redpanda is available."""
    if not KAFKA_AVAILABLE:
        return False
    try:
        from kafka import KafkaProducer

        producer = KafkaProducer(
            bootstrap_servers="redpanda:9092",
            api_version_auto_timeout_ms=5000,
        )
        producer.close()
    except Exception:
        return False
    else:
        return True


def is_redis_available():
    """Check if Redis is available."""
    try:
        import redis

        client = redis.from_url("redis://redis:6379", socket_connect_timeout=2)
        client.ping()
    except Exception:
        return False
    else:
        return True


def is_elasticsearch_available():
    """Check if Elasticsearch is available."""
    try:
        import asyncio

        from elasticsearch import AsyncElasticsearch

        client = AsyncElasticsearch(
            hosts=["http://elasticsearch:9200"],
            verify_certs=False,
            request_timeout=5,
        )

        async def check():
            return await client.ping()

        return asyncio.run(check())
    except Exception:
        return False


# Skip integration tests if services are not available
pytestmark = pytest.mark.skipif(
    not (is_kafka_available() and is_redis_available() and is_elasticsearch_available()),
    reason="Integration test services (Kafka/Redis/Elasticsearch) not available",
)


@pytest.mark.integration
class TestKafkaConnectivity:
    """Test Kafka/Redpanda connectivity."""

    @pytest.fixture(scope="class")
    def kafka_bootstrap(self):
        return "redpanda:9092"

    def test_kafka_connection(self, kafka_bootstrap):
        """Test that we can connect to Kafka/Redpanda."""
        if not KAFKA_AVAILABLE:
            pytest.skip("kafka-python not installed")
        producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap,
            api_version_auto_timeout_ms=5000,
        )
        producer.close()
        assert True

    def test_topic_creation(self, kafka_bootstrap):
        """Test that we can create and list topics."""
        if not KAFKA_AVAILABLE:
            pytest.skip("kafka-python not installed")
        admin = KafkaAdminClient(
            bootstrap_servers=kafka_bootstrap,
            client_id="test-admin",
        )
        topic_name = "test-integration-topic"
        topic = NewTopic(name=topic_name, num_partitions=1, replication_factor=1)
        admin.create_topics([topic])
        topics = admin.list_topics()
        assert topic_name in topics
        admin.delete_topics([topic_name])
        admin.close()


@pytest.mark.integration
class TestRedisConnectivity:
    """Test Redis connectivity."""

    @pytest.fixture(scope="class")
    async def redis_client(self):
        if not REDIS_AVAILABLE:
            pytest.skip("redis not installed")
        import redis.asyncio as redis

        client = redis.from_url("redis://redis:6379", decode_responses=True)
        yield client
        await client.aclose()

    @pytest.mark.asyncio
    async def test_redis_connection(self, redis_client):
        """Test Redis connectivity."""
        await redis_client.ping()
        await redis_client.set("test_key", "test_value")
        value = await redis_client.get("test_key")
        assert value == "test_value"
        await redis_client.delete("test_key")


@pytest.mark.integration
class TestElasticsearchConnectivity:
    """Test Elasticsearch connectivity."""

    @pytest.fixture(scope="class")
    async def es_client(self):
        if not ELASTICSEARCH_AVAILABLE:
            pytest.skip("elasticsearch not installed")
        from elasticsearch import AsyncElasticsearch

        client = AsyncElasticsearch(
            hosts=["http://elasticsearch:9200"],
            verify_certs=False,
        )
        yield client
        await client.close()

    @pytest.mark.asyncio
    async def test_es_connection(self, es_client):
        """Test Elasticsearch connectivity."""
        health = await es_client.cluster.health()
        assert health["status"] in ["green", "yellow"]

    @pytest.mark.asyncio
    async def test_index_operations(self, es_client):
        """Test basic index operations."""
        index_name = "test-integration-index"

        # Create index
        await es_client.indices.create(
            index=f"test-{index_name}",
            body={"mappings": {"properties": {"test_field": {"type": "keyword"}}}},
            ignore=400,
        )

        # Index a document
        await es_client.index(
            index=f"test-{index_name}",
            document={"test_field": "test_value"},
            refresh=True,
        )

        # Search
        result = await es_client.search(
            index=f"test-{index_name}",
            body={"query": {"match_all": {}}},
            size=10,
        )
        assert result["hits"]["total"]["value"] >= 1

        # Cleanup
        await es_client.indices.delete(index=f"test-{index_name}", ignore=[400, 404])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
