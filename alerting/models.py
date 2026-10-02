"""
Alerting & Correlation Domain Logic - Deduplication, enrichment, routing.

No external ML dependencies so unit tests run fast.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class AlertSeverity(StrEnum):
    """Alert severity levels (aligned with syslog/RFC 5424)."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    ALERT = "alert"
    EMERGENCY = "emergency"


class AlertStatus(StrEnum):
    """Alert lifecycle status."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    CLOSED = "closed"


@dataclass(slots=True)
class AlertingConfig:
    """Configuration for the alerting service."""

    # Deduplication
    dedup_window_seconds: int = 300  # 5 minutes
    dedup_key_fields: list[str] = field(
        default_factory=lambda: [
            "alert_type",
            "flow_key",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
        ]
    )

    # Correlation
    correlation_window_seconds: int = 3600  # 1 hour
    min_correlation_score: float = 0.7

    # Enrichment
    enrichment_timeout_seconds: int = 5
    enable_ipwhois: bool = True
    enable_whois: bool = True
    enable_stix: bool = True
    enable_misp: bool = False  # requires MISP instance

    # Routing
    default_severity: AlertSeverity = AlertSeverity.WARNING
    severity_mapping: dict[str, AlertSeverity] = field(
        default_factory=lambda: {
            "fast_path": AlertSeverity.WARNING,
            "deep_path": AlertSeverity.ERROR,
            "xgboost_supervised": AlertSeverity.CRITICAL,
        }
    )

    # Output routing
    output_topics: dict[AlertSeverity, str] = field(
        default_factory=lambda: {
            AlertSeverity.DEBUG: "alerts.debug",
            AlertSeverity.INFO: "alerts.info",
            AlertSeverity.NOTICE: "alerts.notice",
            AlertSeverity.WARNING: "alerts.warning",
            AlertSeverity.ERROR: "alerts.error",
            AlertSeverity.CRITICAL: "alerts.critical",
            AlertSeverity.ALERT: "alerts.alert",
            AlertSeverity.EMERGENCY: "alerts.emergency",
        }
    )

    # Redis
    redis_url: str = "redis://redis:6379"
    dedup_ttl_seconds: int = 86400  # 24 hours


@dataclass(slots=True)
class EnrichedAlert:
    """An alert after enrichment."""

    # Original alert fields
    alert_type: str
    flow_key: str
    timestamp: float
    is_anomaly: bool
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: int | None = None

    # Alert-specific fields (varies by detector)
    anomaly_score: float | None = None
    reconstruction_error: float | None = None
    anomaly_probability: float | None = None
    model_version: str | None = None
    inference_time_ms: float | None = None

    # Enrichment fields
    severity: AlertSeverity = AlertSeverity.WARNING
    status: AlertStatus = AlertStatus.NEW
    dedup_key: str = ""
    dedup_count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Enrichment data
    src_ip_enrichment: dict[str, Any] | None = None
    dst_ip_enrichment: dict[str, Any] | None = None
    stix_indicators: list[dict[str, Any]] = field(default_factory=list)
    misp_events: list[dict[str, Any]] = field(default_factory=list)

    # Correlation
    correlated_alerts: list[str] = field(default_factory=list)
    correlation_score: float = 0.0

    # Routing
    output_topic: str = ""


@dataclass(slots=True)
class CorrelationGroup:
    """A group of correlated alerts."""

    group_id: str
    alerts: list[EnrichedAlert]
    created_at: float
    updated_at: float
    correlation_score: float
    primary_alert: EnrichedAlert | None = None


def generate_dedup_key(alert: dict[str, Any], key_fields: list[str]) -> str:
    """Generate a deduplication key from alert fields."""
    values = []
    for key_field in key_fields:
        value = alert.get(key_field)
        if value is not None:
            values.append(f"{key_field}={value}")
    key_str = "|".join(sorted(values))
    return hashlib.sha256(key_str.encode()).hexdigest()[:32]


def generate_correlation_id(alerts: list[EnrichedAlert]) -> str:
    """Generate a correlation group ID from multiple alerts."""
    flow_keys = sorted({a.flow_key for a in alerts if a.flow_key})
    ip_pairs = sorted({(a.src_ip, a.dst_ip) for a in alerts if a.src_ip and a.dst_ip})
    combined = f"flows={','.join(flow_keys)}|ips={','.join(f'{s}->{d}' for s, d in ip_pairs)}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def enrich_ip_whois(ip: str) -> dict[str, Any] | None:
    """Enrich an IP with WHOIS data (placeholder for ipwhois)."""
    # In real implementation, use ipwhois library
    return {
        "ip": ip,
        "asn": None,
        "asn_description": None,
        "network": None,
        "country": None,
        "registry": None,
        "enriched_at": datetime.utcnow().isoformat(),
    }


def enrich_ip_whois_domain(ip: str) -> dict[str, Any] | None:
    """Enrich an IP with domain WHOIS data (placeholder for python-whois)."""
    return {
        "ip": ip,
        "domain": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "enriched_at": datetime.utcnow().isoformat(),
    }


def create_stix_indicator(alert: EnrichedAlert) -> dict[str, Any] | None:
    """Create a STIX 2.1 indicator from an enriched alert."""
    if not alert.is_anomaly:
        return None

    pattern_parts = []
    if alert.src_ip:
        pattern_parts.append(f"[ipv4-addr:value = '{alert.src_ip}']")
    if alert.dst_ip:
        pattern_parts.append(f"[ipv4-addr:value = '{alert.dst_ip}']")
    if alert.src_port:
        pattern_parts.append(f"[network-traffic:src_port = {alert.src_port}]")
    if alert.dst_port:
        pattern_parts.append(f"[network-traffic:dst_port = {alert.dst_port}]")

    if not pattern_parts:
        return None

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{alert.flow_key}",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"Network Anomaly: {alert.alert_type}",
        "description": f"Detected by {alert.alert_type} with severity {alert.severity.value}",
        "indicator_types": ["malicious-activity", "anomalous-activity"],
        "pattern": " OR ".join(pattern_parts),
        "pattern_type": "stix",
        "valid_from": datetime.utcnow().isoformat() + "Z",
        "labels": ["network-anomaly", alert.alert_type],
    }


def calculate_correlation_score(a1: EnrichedAlert, a2: EnrichedAlert) -> float:
    """Calculate correlation score between two alerts (0.0 to 1.0)."""
    score = 0.0
    factors = 0

    # Same flow key
    if a1.flow_key and a1.flow_key == a2.flow_key:
        score += 0.5
        factors += 1

    # Same IP pair
    if a1.src_ip and a1.dst_ip and a1.src_ip == a2.src_ip and a1.dst_ip == a2.dst_ip:
        score += 0.3
        factors += 1
    elif a1.src_ip and a1.src_ip == a2.src_ip or a1.dst_ip and a1.dst_ip == a2.dst_ip:
        score += 0.15
        factors += 1

    # Same port
    if a1.dst_port and a1.dst_port == a2.dst_port:
        score += 0.1
        factors += 1

    # Same protocol
    if a1.protocol and a1.protocol == a2.protocol:
        score += 0.05
        factors += 1

    # Time proximity (within 1 hour)
    time_diff = abs(a1.timestamp - a2.timestamp)
    if time_diff < 3600:
        score += 0.1 * (1 - time_diff / 3600)
        factors += 1

    return score / max(factors, 1) if factors > 0 else 0.0


def route_alert(alert: EnrichedAlert, config: AlertingConfig) -> str:
    """Determine the output topic for an alert based on severity."""
    return config.output_topics.get(alert.severity, "alerts.warning")


def merge_alerts(existing: EnrichedAlert, new: EnrichedAlert) -> EnrichedAlert:
    """Merge a new alert into an existing deduplicated alert."""
    existing.dedup_count += 1
    existing.last_seen = max(existing.last_seen, new.last_seen)
    # Keep the highest severity (compare by enum member order)
    severity_order = {s: i for i, s in enumerate(AlertSeverity)}
    if severity_order[new.severity] > severity_order[existing.severity]:
        existing.severity = new.severity
    # Merge correlation
    for corr in new.correlated_alerts:
        if corr not in existing.correlated_alerts:
            existing.correlated_alerts.append(corr)
    existing.correlation_score = max(existing.correlation_score, new.correlation_score)
    return existing


def is_dedup_expired(alert: EnrichedAlert, window_seconds: int) -> bool:
    """Check if a deduplication entry has expired."""
    now = time.time()
    return (now - alert.last_seen) > window_seconds
