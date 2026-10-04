"""Elasticsearch test helper for E2E tests."""

from elasticsearch import AsyncElasticsearch


class ElasticsearchTestHelper:
    """Helper for managing Elasticsearch indices in E2E tests."""

    def __init__(
        self,
        hosts: list[str] | str = "http://localhost:9200",
        index_prefix: str = "e2e-test-",
    ) -> None:
        if isinstance(hosts, str):
            hosts = [hosts]
        self.hosts = hosts
        self.index_prefix = index_prefix
        self._client: AsyncElasticsearch | None = None
        self._created_indices: list[str] = []

    async def connect(self) -> None:
        """Initialize Elasticsearch client."""
        self._client = AsyncElasticsearch(
            hosts=self.hosts,
            verify_certs=False,
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        await self._client.ping()

    async def disconnect(self) -> None:
        """Clean up and disconnect."""
        await self._cleanup_indices()
        if self._client:
            await self._client.close()

    async def _cleanup_indices(self) -> None:
        """Delete all created indices."""
        for index in self._created_indices.copy():
            await self.delete_index(index.replace(self.index_prefix, ""))

    async def cleanup_all(self) -> None:
        """Delete all created indices."""
        await self._cleanup_indices()

    def _prefixed(self, name: str) -> str:
        """Add prefix to index name if not already present."""
        if name.startswith(self.index_prefix):
            return name
        return f"{self.index_prefix}{name}"

    async def create_index(
        self,
        name: str,
        mappings: dict | None = None,
        settings: dict | None = None,
    ) -> str:
        """Create an index with optional mappings and settings."""
        full_name = self._prefixed(name)
        body = {}
        if mappings:
            body["mappings"] = mappings
        if settings:
            body["settings"] = settings

        try:
            await self._client.indices.create(index=full_name, body=body)
            self._created_indices.append(full_name)
        except Exception as e:
            if "already exists" not in str(e).lower():
                raise
        return full_name

    async def delete_index(self, name: str) -> None:
        """Delete an index."""
        full_name = self._prefixed(name)
        from contextlib import suppress

        with suppress(Exception):
            await self._client.indices.delete(index=full_name)
            if full_name in self._created_indices:
                self._created_indices.remove(full_name)

    async def index_document(
        self,
        index: str,
        document: dict,
        doc_id: str | None = None,
    ) -> dict:
        """Index a document."""
        return await self._client.index(
            index=self._prefixed(index),
            document=document,
            id=doc_id,
            refresh="wait_for",
        )

    async def bulk_index(self, index: str, documents: list[dict]) -> dict:
        """Bulk index documents."""
        actions = []
        for doc in documents:
            action = {"index": {"_index": self._prefixed(index)}}
            if "_id" in doc:
                action["index"]["_id"] = doc.pop("_id")
            actions.append(action)
            actions.append(doc)

        return await self._client.bulk(operations=actions, refresh="wait_for")

    async def search(
        self,
        index: str,
        query: dict | None = None,
        size: int = 100,
        sort: list | None = None,
    ) -> dict:
        """Search documents."""
        body = {"size": 10000}
        if query:
            body["query"] = query
        if sort:
            body["sort"] = sort

        return await self._client.search(
            index=self._prefixed(index),
            body=body,
            size=size,
            sort=sort,
        )

    async def count(self, index: str, query: dict | None = None) -> int:
        """Count documents matching query."""
        result = await self._client.count(
            index=self._prefixed(index),
            query=query,
        )
        return result["count"]

    async def delete_document(self, index: str, doc_id: str) -> bool:
        """Delete a document by ID."""
        try:
            await self._client.delete(index=self._prefixed(index), id=doc_id)
        except Exception:
            return False
        else:
            return True

    async def refresh_index(self, index: str) -> None:
        """Refresh index to make changes visible."""
        await self._client.indices.refresh(index=self._prefixed(index))

    async def index_exists(self, index: str) -> bool:
        """Check if index exists."""
        return await self._client.indices.exists(index=self._prefixed(index))

    async def get_mapping(self, index: str) -> dict:
        """Get index mapping."""
        return await self._client.indices.get_mapping(index=self._prefixed(index))

    async def delete_by_query(self, index: str, query: dict) -> int:
        """Delete documents matching query."""
        result = await self._client.delete_by_query(
            index=self._prefixed(index),
            query=query,
            refresh=True,
        )
        return result["deleted"]

    async def get_index_stats(self, index: str) -> dict:
        """Get index statistics."""
        stats = await self._client.indices.stats(index=self._prefixed(index))
        return stats["indices"].get(self.index_prefix + index, {})
