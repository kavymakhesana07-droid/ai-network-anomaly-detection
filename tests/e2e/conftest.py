"""E2E test configuration and fixtures."""

import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio

from tests.e2e.helpers.elasticsearch import ElasticsearchTestHelper
from tests.e2e.helpers.kafka import KafkaTestHelper
from tests.e2e.helpers.redis import RedisTestHelper


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def kafka_helper() -> AsyncGenerator[KafkaTestHelper, None]:
    """Kafka test helper with topic management."""
    helper = KafkaTestHelper(bootstrap_servers="localhost:9092", test_topics_prefix="e2e-test-")
    await helper.connect()
    yield helper
    await helper.disconnect()


@pytest_asyncio.fixture(scope="session")
async def redis_helper() -> AsyncGenerator[RedisTestHelper, None]:
    """Redis test helper for caching/state."""
    helper = RedisTestHelper(url="redis://localhost:6379", key_prefix="e2e-test:")
    await helper.connect()
    yield helper
    await helper.disconnect()


@pytest_asyncio.fixture(scope="session")
async def es_helper() -> AsyncGenerator[ElasticsearchTestHelper, None]:
    """Elasticsearch test helper for SIEM output verification."""
    helper = ElasticsearchTestHelper(
        hosts=["http://localhost:9200"], index_prefix="e2e-test-network-alerts"
    )
    await helper.connect()
    yield helper
    await helper.disconnect()


@pytest.fixture(scope="session")
def test_config() -> dict:
    """Test configuration."""
    return {
        "kafka_brokers": "localhost:9092",
        "redis_url": "redis://localhost:6379",
        "elasticsearch_url": "http://localhost:9200",
        "mlflow_url": "http://localhost:5000",
        "test_timeout": 300,
        "poll_interval": 5,
    }
