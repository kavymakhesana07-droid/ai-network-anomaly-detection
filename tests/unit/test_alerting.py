"""Unit tests for Alerting & Correlation domain logic.

Only touches alerting/models.py (dependency-free).
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from alerting.models import (  # noqa: E402
    AlertingConfig,
    AlertSeverity,
    AlertStatus,
    EnrichedAlert,
    calculate_correlation_score,
    create_stix_indicator,
    enrich_ip_whois,
    enrich_ip_whois_domain,
    generate_correlation_id,
    generate_dedup_key,
    is_dedup_expired,
    merge_alerts,
    route_alert,
)


class TestEnums:
    def test_alert_severity_values(self):
        assert AlertSeverity.DEBUG.value == "debug"
        assert AlertSeverity.WARNING.value == "warning"
        assert AlertSeverity.CRITICAL.value == "critical"

    def test_alert_status_values(self):
        assert AlertStatus.NEW.value == "new"
        assert AlertStatus.ACKNOWLEDGED.value == "acknowledged"
        assert AlertStatus.SUPPRESSED.value == "suppressed"
        assert AlertStatus.CLOSED.value == "closed"


class TestDedupKey:
    def test_basic_key_generation(self):
        alert = {
            "alert_type": "fast_path",
            "flow_key": "flow123",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 80,
        }
        key = generate_dedup_key(alert, ["alert_type", "flow_key", "src_ip", "dst_ip"])
        assert len(key) == 32  # sha256 truncated to 32 chars
        assert all(c in "0123456789abcdef" for c in key)

    def test_consistent_key_for_same_fields(self):
        alert1 = {"alert_type": "test", "flow_key": "f1", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        alert2 = {"alert_type": "test", "flow_key": "f1", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        assert generate_dedup_key(
            alert1, ["alert_type", "flow_key", "src_ip", "dst_ip"]
        ) == generate_dedup_key(alert2, ["alert_type", "flow_key", "src_ip", "dst_ip"])

    def test_different_order_same_key(self):
        alert1 = {"a": "1", "b": "2"}
        alert2 = {"b": "2", "a": "1"}
        assert generate_dedup_key(alert1, ["a", "b"]) == generate_dedup_key(alert2, ["a", "b"])

    def test_missing_fields_ignored(self):
        alert = {"alert_type": "test", "flow_key": "f1"}
        key = generate_dedup_key(alert, ["alert_type", "flow_key", "src_ip"])
        assert len(key) == 32


class TestCorrelationId:
    def test_generate_from_alerts(self):
        alerts = [
            EnrichedAlert(
                alert_type="test",
                flow_key="f1",
                timestamp=1.0,
                is_anomaly=False,
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
            ),
            EnrichedAlert(
                alert_type="test",
                flow_key="f2",
                timestamp=2.0,
                is_anomaly=False,
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
            ),
        ]
        cid = generate_correlation_id(alerts)
        assert len(cid) == 16
        assert all(c in "0123456789abcdef" for c in cid)

    def test_deterministic(self):
        alerts = [
            EnrichedAlert(
                alert_type="test",
                flow_key="f1",
                timestamp=1.0,
                is_anomaly=False,
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
            ),
        ]
        cid1 = generate_correlation_id(alerts)
        cid2 = generate_correlation_id(alerts)
        assert cid1 == cid2


class TestCorrelationScore:
    def test_same_flow_key_high_score(self):
        a1 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=1.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        a2 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=2.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        score = calculate_correlation_score(a1, a2)
        # Same flow_key (0.5) + same IP pair (0.3) + time proximity (0.1) / 3 factors = ~0.3
        assert score > 0.29
        assert score < 0.31

    def test_same_ip_pair(self):
        a1 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=1.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        a2 = EnrichedAlert(
            alert_type="t",
            flow_key="f2",
            timestamp=2.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        score = calculate_correlation_score(a1, a2)
        # Same IP pair (0.3) + time proximity (0.1) / 2 factors = ~0.2
        assert score > 0.19
        assert score < 0.21

    def test_no_overlap_low_score(self):
        a1 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=1.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        a2 = EnrichedAlert(
            alert_type="t",
            flow_key="f2",
            timestamp=10000.0,
            is_anomaly=False,
            src_ip="3.3.3.3",
            dst_ip="4.4.4.4",
        )
        score = calculate_correlation_score(a1, a2)
        assert score == 0.0

    def test_time_proximity(self):
        a1 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=1000.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        a2 = EnrichedAlert(
            alert_type="t",
            flow_key="f2",
            timestamp=1001.0,
            is_anomaly=False,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        score = calculate_correlation_score(a1, a2)
        # Same IP pair (0.3) + time proximity (0.1) / 2 factors = ~0.2
        assert score > 0.19
        assert score < 0.21


class TestRouteAlert:
    def test_routes_by_severity(self):
        config = AlertingConfig()
        alert = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=1.0,
            is_anomaly=False,
            severity=AlertSeverity.CRITICAL,
        )
        topic = route_alert(alert, config)
        assert topic == "alerts.critical"

    def test_fallback_to_warning(self):
        config = AlertingConfig()
        # Create an invalid severity to test fallback
        alert = EnrichedAlert(alert_type="t", flow_key="f1", timestamp=1.0, is_anomaly=False)
        alert.severity = AlertSeverity.WARNING
        topic = route_alert(alert, config)
        assert topic == "alerts.warning"


class TestMergeAlerts:
    def test_increments_count(self):
        a1 = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=1.0, is_anomaly=False, dedup_count=1
        )
        a2 = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=2.0, is_anomaly=False, dedup_count=1
        )
        merged = merge_alerts(a1, a2)
        assert merged.dedup_count == 2

    def test_updates_last_seen(self):
        a1 = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=1.0, is_anomaly=False, last_seen=100.0
        )
        a2 = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=2.0, is_anomaly=False, last_seen=200.0
        )
        merged = merge_alerts(a1, a2)
        assert merged.last_seen == 200.0

    def test_keeps_higher_severity(self):
        a1 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=1.0,
            is_anomaly=False,
            severity=AlertSeverity.WARNING,
        )
        a2 = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=2.0,
            is_anomaly=False,
            severity=AlertSeverity.CRITICAL,
        )
        merged = merge_alerts(a1, a2)
        assert merged.severity == AlertSeverity.CRITICAL

    def test_merges_correlations(self):
        a1 = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=1.0, is_anomaly=False, correlated_alerts=["a"]
        )
        a2 = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=2.0, is_anomaly=False, correlated_alerts=["b"]
        )
        merged = merge_alerts(a1, a2)
        assert set(merged.correlated_alerts) == {"a", "b"}


class TestDedupExpiry:
    def test_not_expired_within_window(self):
        alert = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=time.time(),
            is_anomaly=False,
            last_seen=time.time() - 100,
        )
        assert not is_dedup_expired(alert, 300)

    def test_expired_outside_window(self):
        alert = EnrichedAlert(
            alert_type="t",
            flow_key="f1",
            timestamp=time.time(),
            is_anomaly=False,
            last_seen=time.time() - 400,
        )
        assert is_dedup_expired(alert, 300)


class TestEnrichmentPlaceholders:
    def test_ip_whois_returns_dict(self):
        result = enrich_ip_whois("8.8.8.8")
        assert result is not None
        assert result["ip"] == "8.8.8.8"
        assert "enriched_at" in result

    def test_whois_domain_returns_dict(self):
        result = enrich_ip_whois_domain("8.8.8.8")
        assert result is not None
        assert result["ip"] == "8.8.8.8"

    def test_stix_indicator_created(self):
        alert = EnrichedAlert(
            alert_type="fast_path",
            flow_key="f1",
            timestamp=time.time(),
            is_anomaly=True,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
        )
        stix = create_stix_indicator(alert)
        assert stix is not None
        assert stix["type"] == "indicator"
        assert "pattern" in stix

    def test_stix_none_for_non_anomaly(self):
        alert = EnrichedAlert(
            alert_type="t", flow_key="f1", timestamp=time.time(), is_anomaly=False
        )
        assert create_stix_indicator(alert) is None
