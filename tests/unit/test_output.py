"""Unit tests for output integrations domain logic.

Only touches output/models.py (dependency-free).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from output.models import (  # noqa: E402
    DashboardConfig,
    IntegrationConfig,
    OutputFormat,
    SIEMOutputConfig,
    SIEMType,
    _extract_asn,
    _extract_geo,
    _map_severity_to_risk,
    _protocol_number_to_name,
    compute_alert_hash,
    create_dashboard_alert,
    create_siem_event,
    format_alert_for_pagerduty,
    format_alert_for_slack,
)


class TestEnums:
    def test_output_format_values(self):
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.ECS.value == "ecs"
        assert OutputFormat.CEF.value == "cef"
        assert OutputFormat.LEEF.value == "leef"

    def test_siem_type_values(self):
        assert SIEMType.ELASTICSEARCH.value == "elasticsearch"
        assert SIEMType.OPENSEARCH.value == "opensearch"
        assert SIEMType.SPLUNK.value == "splunk"


class TestConfigDefaults:
    def test_dashboard_config(self):
        cfg = DashboardConfig()
        assert cfg.host == "0.0.0.0"  # noqa: S104 - expected default
        assert cfg.port == 8501
        assert cfg.max_alerts_display == 1000

    def test_siem_config(self):
        cfg = SIEMOutputConfig()
        assert cfg.siem_type == SIEMType.ELASTICSEARCH
        assert cfg.output_format == OutputFormat.ECS
        assert cfg.batch_size == 100

    def test_integration_config(self):
        cfg = IntegrationConfig()
        assert cfg.min_severity == "warning"
        assert "slack" in cfg.enabled_channels

    def test_api_config(self):
        from output.models import APIConfig

        cfg = APIConfig()
        assert cfg.host == "0.0.0.0"  # noqa: S104 - expected default
        assert cfg.port == 8000
        assert cfg.rate_limit_requests == 100


class TestDashboardAlert:
    def test_create_from_raw_alert(self):
        raw = {
            "alert_type": "fast_path",
            "flow_key": "test_flow",
            "timestamp": 1000000.0,
            "is_anomaly": True,
            "severity": "critical",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": 6,
            "anomaly_score": 0.95,
            "reconstruction_error": None,
            "anomaly_probability": None,
            "model_version": "1.0.0",
            "inference_time_ms": 1.5,
            "status": "new",
            "src_ip_enrichment": {"asn": 12345},
            "dst_ip_enrichment": {"asn": 67890},
            "stix_indicators": [{"id": "indicator--1"}],
            "correlated_alerts": ["alert1", "alert2"],
            "correlation_score": 0.85,
        }
        alert = create_dashboard_alert(raw)
        assert alert.alert_type == "fast_path"
        assert alert.flow_key == "test_flow"
        assert alert.is_anomaly is True
        assert alert.severity == "critical"
        assert alert.src_ip == "1.1.1.1"
        assert alert.anomaly_score == 0.95
        assert alert.model_version == "1.0.0"
        assert alert.stix_indicators == [{"id": "indicator--1"}]
        assert alert.correlated_alerts == ["alert1", "alert2"]
        assert alert.correlation_score == 0.85


class TestSIEMEvent:
    def test_create_siem_event_ecs(self):
        raw = {
            "alert_type": "deep_path",
            "timestamp": 1000000.0,
            "is_anomaly": True,
            "severity": "error",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1234,
            "dst_port": 443,
            "protocol": 6,
            "model_version": "2.0.0",
            "inference_time_ms": 5.0,
            "anomaly_score": 0.9,
            "reconstruction_error": 0.05,
            "src_ip_enrichment": {"asn": 12345, "country": "US"},
            "dst_ip_enrichment": {"asn": 67890, "country": "CN"},
            "stix_indicators": [{"id": "indicator--2"}],
            "correlated_alerts": ["alert3"],
            "correlation_score": 0.75,
            "dedup_key": "abc123",
        }
        event = create_siem_event(raw)

        # Check ECS fields (event is SIEMEvent dataclass, event.event is a dict)
        assert event.timestamp.endswith("Z")
        assert event.event["kind"] == "alert"
        assert event.event["category"] == ["network", "intrusion_detection"]
        assert event.event["action"] == "alerted"
        assert event.event["severity"] == "error"
        assert event.source["ip"] == "1.1.1.1"
        assert event.destination["ip"] == "2.2.2.2"
        assert event.network["protocol"] == "tcp"
        assert event.rule["id"] == "deep_path"
        assert event.alert["type"] == "deep_path"
        assert event.enrichment["src_ip"] == {"asn": 12345, "country": "US"}
        assert event.correlation["group_id"] == "abc123"


class TestSeverityMapping:
    def test_risk_score_mapping(self):
        assert _map_severity_to_risk("critical") == 80
        assert _map_severity_to_risk("error") == 60
        assert _map_severity_to_risk("warning") == 40
        assert _map_severity_to_risk("info") == 10
        assert _map_severity_to_risk("debug") == 0
        assert _map_severity_to_risk("unknown") == 40  # default

        # Test dict severity
        assert _map_severity_to_risk({"value": "critical"}) == 80
        assert _map_severity_to_risk({"value": "warning"}) == 40


class TestGeoExtraction:
    def test_extract_geo(self):
        enrichment = {"country": "US", "city": "New York", "latitude": 40.71, "longitude": -74.01}
        geo = _extract_geo(enrichment)
        assert geo["country_iso_code"] == "US"
        assert geo["city_name"] == "New York"
        assert geo["location"]["lat"] == 40.71
        assert geo["location"]["lon"] == -74.01

    def test_extract_geo_none(self):
        assert _extract_geo(None) is None
        assert _extract_geo({}) is None


class TestASNExtraction:
    def test_extract_asn(self):
        enrichment = {"asn": 15169, "asn_description": "Google LLC"}
        asn = _extract_asn(enrichment)
        assert asn["number"] == 15169
        assert asn["organization"] == "Google LLC"

    def test_extract_asn_none(self):
        assert _extract_asn(None) is None


class TestProtocolMapping:
    def test_protocol_names(self):
        assert _protocol_number_to_name(6) == "tcp"
        assert _protocol_number_to_name(17) == "udp"
        assert _protocol_number_to_name(1) == "icmp"
        assert _protocol_number_to_name(47) == "gre"
        assert _protocol_number_to_name(999) == "999"  # unknown
        assert _protocol_number_to_name(None) is None


class TestHashing:
    def test_compute_alert_hash(self):
        alert = {
            "alert_type": "fast_path",
            "flow_key": "flow123",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1234,
            "dst_port": 80,
        }
        hash1 = compute_alert_hash(alert)
        hash2 = compute_alert_hash(alert)
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_hash_changes_with_fields(self):
        alert1 = {"alert_type": "fast_path", "flow_key": "f1", "src_ip": "1.1.1.1"}
        alert2 = {"alert_type": "fast_path", "flow_key": "f2", "src_ip": "1.1.1.1"}
        assert compute_alert_hash(alert1) != compute_alert_hash(alert2)


class TestSlackFormatting:
    def test_format_slack_payload(self):
        alert = {
            "alert_type": "fast_path",
            "flow_key": "flow123",
            "severity": "critical",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1234,
            "dst_port": 80,
            "anomaly_score": 0.95,
            "model_version": "1.0.0",
            "timestamp": 1000000.0,
        }
        payload = format_alert_for_slack(alert)

        assert payload["username"] == "Anomaly Detector"
        assert payload["icon_emoji"] == ":warning:"
        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert "Network Anomaly" in attachment["title"]
        assert attachment["color"] == "#FF0000"
        assert "flow123" in attachment["text"]
        assert "critical" in attachment["text"].lower()


class TestPagerDutyFormatting:
    def test_format_pagerduty_payload(self):
        alert = {
            "alert_type": "xgboost_supervised",
            "flow_key": "flow456",
            "severity": "error",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 5678,
            "dst_port": 22,
            "anomaly_score": None,
            "reconstruction_error": None,
            "anomaly_probability": 0.88,
            "model_version": "2.1.0",
            "timestamp": 2000000.0,
        }
        payload = format_alert_for_pagerduty(alert)

        assert payload["event_action"] == "trigger"
        assert "routing_key" in payload
        assert "dedup_key" in payload
        assert "payload" in payload
        assert payload["payload"]["source"] == "network-anomaly-detector"
        assert payload["payload"]["severity"] == "error"
        assert "anomaly_probability" in str(payload["payload"]["custom_details"])


class TestGeoAndASN:
    def test_geo_extraction(self):
        enrichment = {
            "country": "US",
            "city": "San Francisco",
            "latitude": 37.77,
            "longitude": -122.42,
        }
        geo = _extract_geo(enrichment)
        assert geo["country_iso_code"] == "US"
        assert geo["city_name"] == "San Francisco"
        assert geo["location"]["lat"] == 37.77
        assert geo["location"]["lon"] == -122.42

    def test_asn_extraction(self):
        enrichment = {"asn": 13335, "asn_description": "Cloudflare"}
        asn = _extract_asn(enrichment)
        assert asn["number"] == 13335
        assert asn["organization"] == "Cloudflare"
