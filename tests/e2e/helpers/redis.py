"""Redis test helper for E2E tests."""

import redis.asyncio as redis


class RedisTestHelper:
    """Helper for managing Redis state in E2E tests."""

    def __init__(
        self,
        url: str = "redis://localhost:6379",
        key_prefix: str = "e2e-test:",
    ) -> None:
        self.url = url
        self.key_prefix = key_prefix
        self._client: redis.Redis | None = None
        self._keys: set[str] = set()

    async def connect(self) -> None:
        """Initialize Redis client."""
        self._client = redis.from_url(
            self.url,
            encoding="utf-8",
            decode_responses=True,
        )
        await self._client.ping()

    async def disconnect(self) -> None:
        """Clean up and disconnect."""
        await self._cleanup_keys()
        if self._client:
            await self._client.aclose()

    async def _cleanup_keys(self) -> None:
        """Delete all test keys."""
        from contextlib import suppress

        if self._client and self._keys:
            with suppress(Exception):
                await self._client.delete(*self._keys)
        self._keys.clear()

    async def cleanup_all(self) -> None:
        """Clean up all test keys."""
        await self._cleanup_keys()

    def _prefixed(self, key: str) -> str:
        """Add prefix to key if not already present."""
        if key.startswith(self.key_prefix):
            return key
        return f"{self.key_prefix}{key}"

    async def set(
        self,
        key: str,
        value: str,
        expire: int | None = None,
    ) -> None:
        """Set a key-value pair."""
        prefixed = self._prefixed(key)
        self._keys.add(prefixed)
        if self._client:
            if expire:
                await self._client.set(prefixed, value, ex=expire)
            else:
                await self._client.set(prefixed, value)

    async def get(self, key: str) -> str | None:
        """Get a value by key."""
        if not self._client:
            return None
        return await self._client.get(self._prefixed(key))

    async def delete(self, key: str) -> None:
        """Delete a key."""
        prefixed = self._prefixed(key)
        if self._client:
            await self._client.delete(prefixed)
        self._keys.discard(prefixed)

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        if not self._client:
            return False
        return await self._client.exists(self._prefixed(key)) > 0

    async def incr(self, key: str) -> int:
        """Increment a counter."""
        prefixed = self._prefixed(key)
        self._keys.add(prefixed)
        if self._client:
            return await self._client.incr(prefixed)
        return 0

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on a key."""
        if self._client:
            return await self._client.expire(self._prefixed(key), seconds)
        return False

    async def hset(self, name: str, mapping: dict[str, str]) -> int:
        """Set hash fields."""
        prefixed = self._prefixed(name)
        self._keys.add(prefixed)
        if self._client:
            return await self._client.hset(prefixed, mapping=mapping)
        return 0

    async def hget(self, name: str, key: str) -> str | None:
        """Get hash field."""
        if not self._client:
            return None
        return await self._client.hget(self._prefixed(name), key)

    async def hgetall(self, name: str) -> dict[str, str]:
        """Get all hash fields."""
        if not self._client:
            return {}
        return await self._client.hgetall(self._prefixed(name))

    async def hdel(self, name: str, *keys: str) -> int:
        """Delete hash fields."""
        if self._client:
            return await self._client.hdel(self._prefixed(name), *keys)
        return 0

    async def keys(self, pattern: str = "*") -> list[str]:
        """Find keys matching pattern."""
        if not self._client:
            return []
        prefixed_pattern = self._prefixed(pattern)
        return await self._client.keys(prefixed_pattern)

    async def scan_iter(self, match: str = "*") -> list[str]:
        """Scan keys matching pattern."""
        if not self._client:
            return []
        keys = []
        async for key in self._client.scan_iter(match=self._prefixed(match)):
            keys.append(key)
        return keys
