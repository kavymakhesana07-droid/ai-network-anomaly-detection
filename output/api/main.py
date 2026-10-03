"""FastAPI REST API for Network Anomaly Detection.

Provides REST endpoints for:
- Alert querying and filtering
- Alert details and enrichment
- Model registry queries
- Health checks and metrics
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # API
    host: str = Field(default="0.0.0.0", alias="API_HOST")  # noqa: S104 - required for container networking
    port: int = Field(default=8000, alias="API_PORT")
    log_level: str = Field(default="info", alias="API_LOG_LEVEL")

    # Auth
    enable_auth: bool = Field(default=False, alias="API_ENABLE_AUTH")
    api_keys: str = Field(default="", alias="API_KEYS")
    jwt_secret: str | None = Field(default=None, alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(default=60, alias="JWT_EXPIRATION_MINUTES")

    # Rate limiting
    rate_limit_requests: int = Field(default=100, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")

    # CORS
    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")

    # Data sources
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    redis_url: str = Field(default="redis://redis:6379", alias="REDIS_URL")
    elasticsearch_url: str = Field(default="http://elasticsearch:9200", alias="ELASTICSEARCH_URL")
    elasticsearch_index: str = Field(default="network-alerts", alias="ELASTICSEARCH_INDEX")


class AlertFilterParams(BaseModel):
    """Query parameters for alert filtering."""

    alert_type: str | None = None
    severity: str | None = None
    is_anomaly: bool | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    flow_key: str | None = None
    start_time: float | None = None
    end_time: float | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    sort_by: str = Field(default="timestamp")
    sort_order: str = Field(default="desc")


class AlertResponse(BaseModel):
    """Standard alert response."""

    alerts: list[dict]
    total: int
    limit: int
    offset: int


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    components: dict[str, str]


# Global state
settings = Settings()
redis_client: Any = None
es_client: Any = None


async def get_redis() -> Any:
    global redis_client
    if redis_client is None:
        import redis.asyncio as redis

        redis_client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return redis_client


async def get_es_client() -> Any:
    global es_client
    if es_client is None:
        from elasticsearch import AsyncElasticsearch

        es_client = AsyncElasticsearch(
            hosts=["http://elasticsearch:9200"],
            verify_certs=False,
            request_timeout=30,
        )
    return es_client


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Startup
    logger.info("API service starting")
    yield
    # Shutdown
    logger.info("API service shutting down")


app = FastAPI(
    title="Network Anomaly Detection API",
    description="REST API for querying alerts, models, and system health",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(",") if settings.cors_origins != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Auth dependency
async def verify_api_key(x_api_key: str | None = Header(None)) -> None:
    if settings.enable_auth and settings.api_keys:
        valid_keys = {k.strip() for k in settings.api_keys.split(",")}
        if x_api_key not in valid_keys:
            raise HTTPException(status_code=401, detail="Invalid API key")


# Health check
@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    redis_status = "unknown"
    es_status = "unknown"

    try:
        r = await get_redis()
        await r.ping()
        redis_status = "healthy"
    except Exception:
        redis_status = "unhealthy"

    try:
        es = await get_es_client()
        await es.ping()
        es_status = "healthy"
    except Exception:
        es_status = "unhealthy"

    overall = "healthy" if redis_status == "healthy" and es_status == "healthy" else "degraded"

    return HealthResponse(
        status=overall,
        timestamp=datetime.utcnow().isoformat() + "Z",
        version="1.0.0",
        components={
            "redis": redis_status,
            "elasticsearch": es_status,
            "api": "healthy",
        },
    )


# Alerts endpoints
@app.get(
    "/api/v1/alerts",
    response_model=AlertResponse,
    dependencies=[Depends(verify_api_key)],
    tags=["Alerts"],
)
async def list_alerts(
    alert_type: str | None = Query(None, description="Filter by alert type"),
    severity: str | None = Query(None, description="Filter by severity"),
    is_anomaly: bool | None = Query(None, description="Filter by anomaly flag"),
    src_ip: str | None = Query(None, description="Filter by source IP"),
    dst_ip: str | None = Query(None, description="Filter by destination IP"),
    flow_key: str | None = Query(None, description="Filter by flow key"),
    start_time: float | None = Query(None, description="Start timestamp (epoch)"),
    end_time: float | None = Query(None, description="End timestamp (epoch)"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    sort_by: str = Query("timestamp", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
) -> AlertResponse:
    """List alerts with filtering and pagination."""
    # Build Elasticsearch query
    es = await get_es_client()

    must_clauses = []

    if alert_type:
        must_clauses.append({"term": {"alert.type": alert_type}})
    if severity:
        must_clauses.append({"term": {"event.severity": severity.lower()}})
    if is_anomaly is not None:
        must_clauses.append({"term": {"event.outcome": "success" if is_anomaly else "failure"}})
    if src_ip:
        must_clauses.append({"term": {"source.ip": src_ip}})
    if dst_ip:
        must_clauses.append({"term": {"destination.ip": dst_ip}})
    if flow_key:
        must_clauses.append({"wildcard": {"rule.id": f"*{flow_key}*"}})

    if start_time or end_time:
        range_query = {}
        if start_time:
            range_query["gte"] = datetime.fromtimestamp(start_time).isoformat() + "Z"
        if end_time:
            range_query["lte"] = datetime.fromtimestamp(end_time).isoformat() + "Z"
        must_clauses.append({"range": {"@timestamp": range_query}})

    query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    sort_field = "@timestamp" if sort_by == "timestamp" else sort_by
    sort = [{sort_field: {"order": sort_order}}]

    try:
        response = await es.search(
            index="network-alerts*",
            query=query,
            sort=sort,
            size=limit,
            from_=offset,
            track_total_hits=True,
        )

        total = (
            response["hits"]["total"]["value"]
            if isinstance(response["hits"]["total"], dict)
            else response["hits"]["total"]
        )
        hits = response["hits"]["hits"]

        alerts = [hit["_source"] for hit in hits]

        return AlertResponse(
            alerts=alerts,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.exception("Alert query failed", error=str(exc))
        raise HTTPException(status_code=500, detail="Query failed") from None


@app.get("/api/v1/alerts/{alert_id}", dependencies=[Depends(verify_api_key)], tags=["Alerts"])
async def get_alert(alert_id: str) -> dict:
    """Get a single alert by ID."""
    es = await get_es_client()

    try:
        response = await es.get(index="network-alerts*", id=alert_id)
        return response["_source"]
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Alert not found") from exc


@app.get("/api/v1/alerts/stats/summary", dependencies=[Depends(verify_api_key)], tags=["Alerts"])
async def alert_stats(
    start_time: float | None = Query(None),
    end_time: float | None = Query(None),
) -> dict:
    """Get alert statistics."""
    es = await get_es_client()

    range_query = {}
    if start_time:
        range_query["gte"] = datetime.fromtimestamp(start_time).isoformat() + "Z"
    if end_time:
        range_query["lte"] = datetime.fromtimestamp(end_time).isoformat() + "Z"

    range_clause = {"range": {"@timestamp": range_query}} if range_query else {"match_all": {}}

    try:
        # Total count
        total_resp = await es.count(index="network-alerts*", query=range_clause)
        total = total_resp["count"]

        # By severity
        severity_agg = await es.search(
            index="network-alerts*",
            query=range_clause,
            aggs={
                "by_severity": {"terms": {"field": "event.severity", "size": 10}},
            },
            size=0,
        )
        by_severity = {
            b["key"]: b["doc_count"] for b in severity_agg["aggregations"]["by_severity"]["buckets"]
        }

        # By alert type
        type_agg = await es.search(
            index="network-alerts*",
            query=range_clause,
            aggs={
                "by_type": {"terms": {"field": "alert.type", "size": 10}},
            },
            size=0,
        )
        by_type = {b["key"]: b["doc_count"] for b in type_agg["aggregations"]["by_type"]["buckets"]}

        # By anomaly
        anomaly_agg = await es.search(
            index="network-alerts*",
            query=range_clause,
            aggs={
                "by_anomaly": {"terms": {"field": "event.outcome", "size": 2}},
            },
            size=0,
        )
        by_anomaly = {
            b["key"]: b["doc_count"] for b in anomaly_agg["aggregations"]["by_anomaly"]["buckets"]
        }

    except Exception as exc:
        logger.exception("Stats query failed", error=str(exc))
        raise HTTPException(status_code=500, detail="Stats query failed") from None
    else:
        return {
            "total": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "by_anomaly": by_anomaly,
        }


# Models endpoints
@app.get("/api/v1/models", dependencies=[Depends(verify_api_key)], tags=["Models"])
async def list_models() -> dict:
    """List registered models from MLflow."""
    # This would integrate with model_registry service
    return {
        "models": [],
        "message": "Model registry integration pending",
    }


# Metrics endpoint
@app.get("/metrics", tags=["Metrics"])
async def metrics() -> str:
    """Prometheus metrics endpoint."""
    # In production, use prometheus_client
    return """# HELP api_requests_total Total API requests
# TYPE api_requests_total counter
api_requests_total{endpoint="/health",method="GET"} 0
# HELP alerts_received_total Total alerts received
# TYPE alerts_received_total counter
alerts_received_total 0
"""


def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    uvicorn.run(
        "output.api.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=False,
    )


if __name__ == "__main__":
    main()
