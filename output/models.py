"""
Output Integrations Domain Logic - Dashboard, SIEM, ChatOps.

No external ML dependencies so unit tests run fast.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class OutputFormat(StrEnum):
    """Supported output formats."""

    JSON = "json"
    ECS = "ecs"  # Elastic Common Schema
    CEF = "cef"  # Common Event Format
    LEEF = "leef"  # Log Event Extended Format


class SIEMType(StrEnum):
    """Supported SIEM platforms."""

    ELASTICSEARCH = "elasticsearch"
    OPENSEARCH = "opensearch"
    SPLUNK = "splunk"
    SUMO_LOGIC = "sumo_logic"
    DATADOG = "datadog"


@dataclass(slots=True)
class DashboardConfig:
    """Configuration for the Streamlit dashboard."""

    host: str = "0.0.0.0"  # noqa: S104 - required for container networking
    port: int = 8501
    theme: str = "dark"

    # Data sources
    kafka_brokers: str = "localhost:9092"
    alerts_topic: str = "alerts.enriched"
    redis_url: str = "redis://redis:6379"

    # UI settings
    max_alerts_display: int = 1000
    refresh_interval_seconds: int = 10
    default_time_range_hours: int = 24

    # Feature flags
    enable_real_time: bool = True
    enable_alert_details: bool = True
    enable_correlation_view: bool = True
    enable_stix_view: bool = True


@dataclass(slots=True)
class SIEMOutputConfig:
    """Configuration for SIEM output."""

    # Target
    siem_type: SIEMType = SIEMType.ELASTICSEARCH
    elasticsearch_url: str = "http://elasticsearch:9200"
    elasticsearch_index: str = "network-alerts"
    opensearch_url: str = "http://opensearch:9200"
    opensearch_index: str = "network-alerts"

    # Authentication
    username: str | None = None
    password: str | None = None
    api_key: str | None = None

    # Output format
    output_format: OutputFormat = OutputFormat.ECS
    include_raw_alert: bool = True

    # Batching
    batch_size: int = 100
    flush_interval_seconds: int = 10
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0

    # Index lifecycle
    index_template_name: str = "network-alerts-template"
    ilm_policy_name: str = "network-alerts-ilm"
    rollover_alias: str = "network-alerts"


@dataclass(slots=True)
class IntegrationConfig:
    """Configuration for ChatOps integrations."""

    # Slack
    slack_webhook_url: str | None = None
    slack_channel: str = "#security-alerts"
    slack_username: str = "anomaly-detector"
    slack_icon_emoji: str = ":warning:"

    # PagerDuty
    pagerduty_integration_key: str | None = None
    pagerduty_severity_mapping: dict[str, str] = field(
        default_factory=lambda: {
            "critical": "critical",
            "error": "error",
            "warning": "warning",
            "info": "info",
        }
    )

    # Mattermost
    mattermost_webhook_url: str | None = None
    mattermost_channel: str = "security-alerts"

    # Generic webhook
    webhook_url: str | None = None
    webhook_headers: dict[str, str] = field(default_factory=dict)

    # Filtering
    min_severity: str = "warning"
    enabled_channels: list[str] = field(default_factory=lambda: ["slack"])


@dataclass(slots=True)
class APIConfig:
    """Configuration for the FastAPI REST API."""

    host: str = "0.0.0.0"  # noqa: S104 - required for container networking
    port: int = 8000

    # Auth
    enable_auth: bool = False
    api_keys: list[str] = field(default_factory=list)
    jwt_secret: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 60

    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # CORS
    cors_origins: list[str] = field(default_factory=lambda: ["*"])

    # Data sources
    kafka_brokers: str = "localhost:9092"
    redis_url: str = "redis://redis:6379"
    elasticsearch_url: str = "http://elasticsearch:9200"
    elasticsearch_index: str = "network-alerts"


@dataclass(slots=True)
class DashboardAlert:
    """Alert formatted for dashboard display."""

    alert_id: str
    alert_type: str
    flow_key: str
    timestamp: float
    timestamp_iso: str
    is_anomaly: bool
    severity: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: int | None
    anomaly_score: float | None
    reconstruction_error: float | None
    anomaly_probability: float | None
    model_version: str | None
    inference_time_ms: float | None
    severity: str | None
    status: str | None
    src_ip_enrichment: dict | None
    dst_ip_enrichment: dict | None
    stix_indicators: list[dict] | None
    correlated_alerts: list[str] | None
    correlation_score: float | None


@dataclass(slots=True)
class SIEMEvent:
    """Event formatted for SIEM ingestion (ECS format)."""

    # ECS base fields
    timestamp: str
    event: dict[str, Any] = field(default_factory=dict)
    source: dict[str, Any] = field(default_factory=dict)
    destination: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    host: dict[str, Any] = field(default_factory=dict)
    rule: dict[str, Any] = field(default_factory=dict)
    threat: dict[str, Any] = field(default_factory=dict)
    observer: dict[str, Any] = field(default_factory=dict)

    # Custom fields
    alert: dict[str, Any] = field(default_factory=dict)
    enrichment: dict[str, Any] = field(default_factory=dict)
    correlation: dict[str, Any] = field(default_factory=dict)


def create_dashboard_alert(raw_alert: dict[str, Any]) -> DashboardAlert:
    """Convert raw enriched alert to dashboard format."""
    severity = raw_alert.get("severity", "warning")
    if isinstance(severity, dict):
        severity = severity.get("value", "warning")

    return DashboardAlert(
        alert_id=raw_alert.get("flow_key", "")
        + "_"
        + str(int(raw_alert.get("timestamp", 0) * 1000)),
        alert_type=raw_alert.get("alert_type", "unknown"),
        flow_key=raw_alert.get("flow_key", ""),
        timestamp=raw_alert.get("timestamp", 0),
        timestamp_iso=datetime.fromtimestamp(raw_alert.get("timestamp", 0)).isoformat(),
        is_anomaly=raw_alert.get("is_anomaly", False),
        severity=raw_alert.get("severity", "warning")
        if isinstance(raw_alert.get("severity"), str)
        else raw_alert.get("severity", {}).get("value", "warning"),
        src_ip=raw_alert.get("src_ip"),
        dst_ip=raw_alert.get("dst_ip"),
        src_port=raw_alert.get("src_port"),
        dst_port=raw_alert.get("dst_port"),
        protocol=raw_alert.get("protocol"),
        anomaly_score=raw_alert.get("anomaly_score"),
        reconstruction_error=raw_alert.get("reconstruction_error"),
        anomaly_probability=raw_alert.get("anomaly_probability"),
        model_version=raw_alert.get("model_version"),
        inference_time_ms=raw_alert.get("inference_time_ms"),
        status=raw_alert.get("status", "new"),
        src_ip_enrichment=raw_alert.get("src_ip_enrichment"),
        dst_ip_enrichment=raw_alert.get("dst_ip_enrichment"),
        stix_indicators=raw_alert.get("stix_indicators"),
        correlated_alerts=raw_alert.get("correlated_alerts"),
        correlation_score=raw_alert.get("correlation_score"),
    )


def create_siem_event(raw_alert: dict[str, Any]) -> SIEMEvent:
    """Convert raw enriched alert to ECS-format SIEM event."""
    ts = raw_alert.get("timestamp", 0)
    timestamp = datetime.fromtimestamp(ts).isoformat() + "Z"

    event = SIEMEvent(
        timestamp=timestamp,
        event={
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "type": ["info", "anomaly"],
            "action": "alerted",
            "outcome": "success" if raw_alert.get("is_anomaly") else "failure",
            "severity": raw_alert.get("severity", "warning")
            if isinstance(raw_alert.get("severity"), str)
            else raw_alert.get("severity", {}).get("value", "warning"),
            "risk_score": _map_severity_to_risk(raw_alert.get("severity")),
            "module": "network_anomaly_detection",
            "dataset": "network_anomaly_detection.alert",
        },
        source={
            "ip": raw_alert.get("src_ip"),
            "port": raw_alert.get("src_port"),
            "geo": _extract_geo(raw_alert.get("src_ip_enrichment")),
            "as": _extract_asn(raw_alert.get("src_ip_enrichment")),
        },
        destination={
            "ip": raw_alert.get("dst_ip"),
            "port": raw_alert.get("dst_port"),
            "geo": _extract_geo(raw_alert.get("dst_ip_enrichment")),
            "as": _extract_asn(raw_alert.get("dst_ip_enrichment")),
        },
        network={
            "protocol": _protocol_number_to_name(raw_alert.get("protocol")),
            "transport": "tcp" if raw_alert.get("protocol") in (6,) else "udp",
            "direction": "outbound",
        },
        host={
            "name": "network-anomaly-detector",
        },
        rule={
            "id": raw_alert.get("alert_type"),
            "name": raw_alert.get("alert_type", "").replace("_", " ").title(),
            "description": f"Network anomaly detected by {raw_alert.get('alert_type')}",
            "ruleset": "network_anomaly_detection",
        },
        threat={
            "indicator": {
                "ip": [raw_alert.get("src_ip"), raw_alert.get("dst_ip")],
            },
            "enrichment": raw_alert.get("src_ip_enrichment") or raw_alert.get("dst_ip_enrichment"),
        },
        observer={
            "name": "network-anomaly-detector",
            "type": "network_sensor",
            "vendor": "custom",
            "version": raw_alert.get("model_version", "unknown"),
        },
        alert={
            "type": raw_alert.get("alert_type"),
            "score": raw_alert.get("anomaly_score")
            or raw_alert.get("reconstruction_error")
            or raw_alert.get("anomaly_probability"),
            "model_version": raw_alert.get("model_version"),
            "inference_time_ms": raw_alert.get("inference_time_ms"),
        },
        enrichment={
            "src_ip": raw_alert.get("src_ip_enrichment"),
            "dst_ip": raw_alert.get("dst_ip_enrichment"),
            "stix": raw_alert.get("stix_indicators"),
        },
        correlation={
            "correlated_alerts": raw_alert.get("correlated_alerts"),
            "correlation_score": raw_alert.get("correlation_score"),
            "group_id": raw_alert.get("dedup_key"),
        },
    )
    return event


def _map_severity_to_risk(severity: str | dict | None) -> int | None:
    """Map severity to risk score (0-100)."""
    if severity is None:
        return None
    if isinstance(severity, dict):
        severity = severity.get("value", "warning")
    mapping = {
        "debug": 0,
        "info": 10,
        "notice": 20,
        "warning": 40,
        "error": 60,
        "critical": 80,
        "alert": 90,
        "emergency": 100,
    }
    return mapping.get(severity, 40)


def _extract_geo(enrichment: dict | None) -> dict | None:
    if not enrichment:
        return None
    return {
        "country_iso_code": enrichment.get("country"),
        "city_name": enrichment.get("city"),
        "location": {
            "lat": enrichment.get("latitude"),
            "lon": enrichment.get("longitude"),
        }
        if enrichment.get("latitude") and enrichment.get("longitude")
        else None,
    }


def _extract_asn(enrichment: dict | None) -> dict | None:
    if not enrichment:
        return None
    return {
        "number": enrichment.get("asn"),
        "organization": enrichment.get("asn_description"),
    }


def _protocol_number_to_name(proto: int | None) -> str | None:
    if proto is None:
        return None
    mapping = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah"}
    return mapping.get(proto, str(proto))


def compute_alert_hash(alert: dict) -> str:
    """Compute deterministic hash for alert deduplication."""
    # Use stable fields for hash
    stable_fields = {
        "alert_type": alert.get("alert_type"),
        "flow_key": alert.get("flow_key"),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "src_port": alert.get("src_port"),
        "dst_port": alert.get("dst_port"),
    }
    data = json.dumps(stable_fields, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def format_alert_for_slack(alert: dict) -> dict:
    """Format alert for Slack webhook."""
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

    return {
        "username": "Anomaly Detector",
        "icon_emoji": ":warning:",
        "attachments": [
            {
                "color": color_map.get(severity, "#FFA500"),
                "title": f"Network Anomaly: {alert.get('alert_type', 'Unknown')}",
                "text": f"*Flow:* `{alert.get('flow_key', 'N/A')}`\n"
                f"*Severity:* {alert.get('severity', 'warning')}\n"
                f"*Source:* {alert.get('src_ip', 'N/A')}:{alert.get('src_port', 'N/A')}\n"
                f"*Destination:* {alert.get('dst_ip', 'N/A')}:{alert.get('dst_port', 'N/A')}\n"
                f"*Score:* {alert.get('anomaly_score') or alert.get('reconstruction_error') or alert.get('anomaly_probability', 'N/A')}\n"
                f"*Model:* {alert.get('model_version', 'N/A')}",
                "fields": [
                    {
                        "title": "Timestamp",
                        "value": datetime.fromtimestamp(alert.get("timestamp", 0)).isoformat(),
                        "short": True,
                    },
                    {"title": "Model", "value": alert.get("model_version", "N/A"), "short": True},
                ],
                "footer": "Network Anomaly Detection",
                "ts": int(alert.get("timestamp", 0)),
            }
        ],
    }


def format_alert_for_pagerduty(alert: dict) -> dict:
    """Format alert for PagerDuty Events API v2."""
    severity = alert.get("severity", "warning")
    if isinstance(severity, dict):
        severity = severity.get("value", "warning")

    return {
        "routing_key": "",  # Set from config
        "event_action": "trigger",
        "dedup_key": compute_alert_hash(alert),
        "payload": {
            "summary": f"Network Anomaly: {alert.get('alert_type', 'Unknown')} - {alert.get('flow_key', 'N/A')}",
            "source": "network-anomaly-detector",
            "severity": severity,
            "component": "network-anomaly-detector",
            "group": "network-security",
            "class": alert.get("alert_type", "unknown"),
            "custom_details": {
                "flow_key": alert.get("flow_key"),
                "src_ip": alert.get("src_ip"),
                "dst_ip": alert.get("dst_ip"),
                "src_port": alert.get("src_port"),
                "dst_port": alert.get("dst_port"),
                "protocol": alert.get("protocol"),
                "anomaly_score": alert.get("anomaly_score"),
                "reconstruction_error": alert.get("reconstruction_error"),
                "anomaly_probability": alert.get("anomaly_probability"),
                "model_version": alert.get("model_version"),
                "src_ip_enrichment": alert.get("src_ip_enrichment"),
                "dst_ip_enrichment": alert.get("dst_ip_enrichment"),
            },
        },
    }
