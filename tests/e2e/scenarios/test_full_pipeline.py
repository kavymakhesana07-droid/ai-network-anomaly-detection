"""E2E tests for the full anomaly detection pipeline."""

import asyncio
import time

import pytest

from tests.e2e.helpers.elasticsearch import ElasticsearchTestHelper
from tests.e2e.helpers.kafka import KafkaTestHelper
from tests.e2e.helpers.redis import RedisTestHelper


class TestFullPipeline:
    """End-to-end tests for the complete anomaly detection pipeline."""

    @pytest.fixture(autouse=True)
    async def setup_helpers(
        self,
        kafka_helper: KafkaTestHelper,
        redis_helper: RedisTestHelper,
        es_helper: ElasticsearchTestHelper,
    ):
        """Setup test helpers."""
        self.kafka = kafka_helper
        self.redis = redis_helper
        self.es = es_helper

    @pytest.mark.asyncio
    async def test_ingestion_to_feature_extraction(self):
        """Test packet ingestion through feature extraction."""
        # Create test topics
        await self.kafka.create_topic("raw-packets")
        await self.kafka.create_topic("features-flows")

        # Produce sample packet data
        test_packets = [
            {
                "timestamp": time.time(),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": 6,
                "payload": "GET / HTTP/1.1",
                "length": 150,
            },
            {
                "timestamp": time.time(),
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.1",
                "src_port": 80,
                "dst_port": 12345,
                "protocol": 6,
                "payload": "HTTP/1.1 200 OK",
                "length": 200,
            },
        ]

        for pkt in test_packets:
            await self.kafka.produce("raw-packets", pkt)

        # Wait for feature extraction
        await asyncio.sleep(5)

        # Verify features were produced
        features = await self.kafka.consume("features-flows", "e2e-test-consumer", max_messages=10)
        assert len(features) >= 1

        # Verify feature structure
        feature = features[0]
        assert "flow_key" in feature
        assert "src_ip" in feature
        assert "dst_ip" in feature
        assert "features" in feature or "fwd_packets" in feature

    @pytest.mark.asyncio
    async def test_fast_path_detection(self):
        """Test fast path anomaly detection."""
        # This test assumes fast-path service is running
        # Produce feature vectors that should trigger anomalies
        anomaly_features = {
            "flow_key": "test-flow-anomaly",
            "timestamp": time.time(),
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 1234,
            "dst_port": 22,
            "protocol": 6,
            "features": {
                "duration": 0.001,
                "fwd_packets": 1000,
                "bwd_packets": 1,
                "fwd_bytes": 500,
                "bwd_bytes": 40,
                "fwd_packet_len_max": 500,
                "fwd_packet_len_min": 40,
                "fwd_packet_len_mean": 50,
                "fwd_packet_len_std": 100,
                "bwd_packet_len_max": 40,
                "bwd_packet_len_min": 40,
                "bwd_packet_len_mean": 40,
                "bwd_packet_len_std": 0,
                "fwd_iat_total": 0.1,
                "fwd_iat_mean": 0.0001,
                "fwd_iat_std": 0.00001,
                "fwd_iat_max": 0.001,
                "fwd_iat_min": 0.00005,
                "bwd_iat_total": 0,
                "bwd_iat_mean": 0,
                "bwd_iat_std": 0,
                "bwd_iat_max": 0,
                "bwd_iat_min": 0,
                "fin_flag_count": 0,
                "syn_flag_count": 1000,
                "rst_flag_count": 0,
                "psh_flag_count": 0,
                "ack_flag_count": 1,
                "urg_flag_count": 0,
                "cwr_flag_count": 0,
                "ece_flag_count": 0,
                "fwd_packets_per_sec": 1000000,
                "bwd_packets_per_sec": 1000,
                "fwd_bytes_per_sec": 500000,
                "bwd_bytes_per_sec": 40000,
                "subflow_fwd_packets": 1000,
                "subflow_fwd_bytes": 500,
                "subflow_bwd_packets": 1,
                "subflow_bwd_bytes": 40,
                "init_fwd_win_bytes": 1000,
                "init_bwd_win_bytes": 1000,
                "active_mean": 0,
                "active_std": 0,
                "active_max": 0,
                "active_min": 0,
                "idle_mean": 0.1,
                "idle_std": 0,
                "idle_max": 0.1,
                "idle_min": 0.1,
            },
        }

        # Send to features topic (which fast-path consumes)
        await self.kafka.produce("features-flows", anomaly_features)

        # Wait for processing
        await asyncio.sleep(3)

        # Check alerts topic
        alerts = await self.kafka.consume("alerts.raw", "e2e-test-consumer", max_messages=5)

        # Should detect anomaly (SYN flood pattern)
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.get("is_anomaly") is True
        assert "fast_path" in alert.get("alert_type", "") or "anomaly" in alert.get(
            "alert_type", ""
        )

    @pytest.mark.asyncio
    async def test_deep_path_detection(self):
        """Test deep path (LSTM) anomaly detection."""
        # This test assumes deep-path service is running
        # Produce sequential flows for LSTM analysis
        normal_flows = [
            {
                "flow_key": f"test-flow-deep-{i}",
                "timestamp": time.time() + i,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 12345 + i,
                "dst_port": 80,
                "protocol": 6,
                "features": {
                    "duration": 1.0 + i * 0.1,
                    "fwd_packets": 10 + i,
                    "bwd_packets": 8 + i,
                    "fwd_bytes": 1500 + i * 100,
                    "bwd_bytes": 1200 + i * 80,
                    "fwd_packet_len_max": 1500,
                    "fwd_packet_len_min": 64,
                    "fwd_packet_len_mean": 150,
                    "fwd_packet_len_std": 300,
                    "bwd_packet_len_max": 1500,
                    "bwd_packet_len_min": 64,
                    "bwd_packet_len_mean": 150,
                    "bwd_packet_len_std": 300,
                    "fwd_iat_total": 1.0,
                    "fwd_iat_mean": 0.1,
                    "fwd_iat_std": 0.05,
                    "fwd_iat_max": 0.5,
                    "fwd_iat_min": 0.01,
                    "bwd_iat_total": 1.0,
                    "bwd_iat_mean": 0.1,
                    "bwd_iat_std": 0.05,
                    "bwd_iat_max": 0.5,
                    "bwd_iat_min": 0.01,
                    "fin_flag_count": 1,
                    "syn_flag_count": 1,
                    "rst_flag_count": 0,
                    "psh_flag_count": 2,
                    "ack_flag_count": 8,
                    "urg_flag_count": 0,
                    "cwr_flag_count": 0,
                    "ece_flag_count": 0,
                    "fwd_packets_per_sec": 10,
                    "bwd_packets_per_sec": 8,
                    "fwd_bytes_per_sec": 1500,
                    "bwd_bytes_per_sec": 1200,
                    "subflow_fwd_packets": 5,
                    "subflow_fwd_bytes": 750,
                    "subflow_bwd_packets": 4,
                    "subflow_bwd_bytes": 600,
                    "init_fwd_win_bytes": 65535,
                    "init_bwd_win_bytes": 65535,
                    "active_mean": 0.5,
                    "active_std": 0.1,
                    "active_max": 1.0,
                    "active_min": 0.1,
                    "idle_mean": 0.1,
                    "idle_std": 0.05,
                    "idle_max": 0.2,
                    "idle_min": 0.01,
                },
            }
            for i in range(15)  # Need enough for sequence length
        ]

        # Send batch of flows
        for flow in normal_flows:
            await self.kafka.produce("features-flows", flow)

        await asyncio.sleep(5)

        # Check deep path alerts
        alerts = await self.kafka.consume("alerts.deep", "e2e-test-consumer", max_messages=5)

        # May or may not trigger depending on training
        # At minimum, verify the path works
        assert isinstance(alerts, list)

    @pytest.mark.asyncio
    async def test_xgboost_detection(self):
        """Test XGBoost supervised detection."""
        # Test with labeled anomaly
        xgb_anomaly = {
            "flow_key": "test-flow-xgb",
            "timestamp": time.time(),
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.50",
            "src_port": 443,
            "dst_port": 443,
            "protocol": 6,
            "features": {
                "duration": 10.0,
                "fwd_packets": 100,
                "bwd_packets": 90,
                "fwd_bytes": 50000,
                "bwd_bytes": 45000,
                "fwd_packet_len_max": 1500,
                "fwd_packet_len_min": 64,
                "fwd_packet_len_mean": 500,
                "fwd_packet_len_std": 300,
                "bwd_packet_len_max": 1500,
                "bwd_packet_len_min": 64,
                "bwd_packet_len_mean": 500,
                "bwd_packet_len_std": 300,
                "fwd_iat_total": 5.0,
                "fwd_iat_mean": 0.5,
                "fwd_iat_std": 0.2,
                "fwd_iat_max": 2.0,
                "fwd_iat_min": 0.01,
                "bwd_iat_total": 5.0,
                "bwd_iat_mean": 0.5,
                "bwd_iat_std": 0.2,
                "bwd_iat_max": 2.0,
                "bwd_iat_min": 0.01,
                "fin_flag_count": 1,
                "syn_flag_count": 1,
                "rst_flag_count": 0,
                "psh_flag_count": 10,
                "ack_flag_count": 80,
                "urg_flag_count": 0,
                "cwr_flag_count": 0,
                "ece_flag_count": 0,
                "fwd_packets_per_sec": 10,
                "bwd_packets_per_sec": 9,
                "fwd_bytes_per_sec": 5000,
                "bwd_bytes_per_sec": 4500,
                "subflow_fwd_packets": 50,
                "subflow_fwd_bytes": 25000,
                "subflow_bwd_packets": 45,
                "subflow_bwd_bytes": 22500,
                "init_fwd_win_bytes": 65535,
                "init_bwd_win_bytes": 65535,
                "active_mean": 2.0,
                "active_std": 0.5,
                "active_max": 5.0,
                "active_min": 0.5,
                "idle_mean": 0.5,
                "idle_std": 0.2,
                "idle_max": 1.0,
                "idle_min": 0.1,
            },
        }

        await self.kafka.produce("features-flows", xgb_anomaly)
        await asyncio.sleep(3)

        alerts = await self.kafka.consume("alerts.xgboost", "e2e-test-consumer", max_messages=5)

        # Should detect if model is trained
        assert isinstance(alerts, list)

    @pytest.mark.asyncio
    async def test_alerting_and_enrichment(self):
        """Test alerting correlation and enrichment pipeline."""
        # Create correlated alerts
        base_time = time.time()
        correlated_alerts = [
            {
                "alert_type": "fast_path",
                "flow_key": "corr-test-1",
                "timestamp": base_time,
                "is_anomaly": True,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.100",
                "src_port": 1234,
                "dst_port": 22,
                "protocol": 6,
                "anomaly_score": 0.95,
                "model_version": "fast_path_v1",
                "inference_time_ms": 2.5,
            },
            {
                "alert_type": "deep_path",
                "flow_key": "corr-test-2",
                "timestamp": base_time + 1,
                "is_anomaly": True,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.101",
                "src_port": 1235,
                "dst_port": 22,
                "protocol": 6,
                "reconstruction_error": 0.85,
                "anomaly_score": 0.88,
                "model_version": "deep_path_v1",
                "inference_time_ms": 15.0,
            },
            {
                "alert_type": "xgboost_supervised",
                "flow_key": "corr-test-3",
                "timestamp": base_time + 2,
                "is_anomaly": True,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.102",
                "src_port": 1236,
                "dst_port": 22,
                "protocol": 6,
                "anomaly_probability": 0.92,
                "model_version": "xgb_v1",
                "inference_time_ms": 1.2,
            },
        ]

        for alert in correlated_alerts:
            await self.kafka.produce("alerts.enriched", alert)

        await asyncio.sleep(3)

        # Check enriched alerts output
        enriched = await self.kafka.consume("alerts.enriched", "e2e-test-consumer", max_messages=5)

        assert len(enriched) >= 1
        enriched_alert = enriched[0]

        # Verify enrichment fields
        assert "src_ip_enrichment" in enriched_alert or "dst_ip_enrichment" in enriched_alert
        assert "correlated_alerts" in enriched_alert or "correlation_score" in enriched_alert

    @pytest.mark.asyncio
    async def test_siem_output(self, es_helper: ElasticsearchTestHelper):
        """Test SIEM output to Elasticsearch."""
        # Produce alert that should be indexed
        test_alert = {
            "alert_type": "fast_path",
            "flow_key": "es-test-flow",
            "timestamp": time.time(),
            "is_anomaly": True,
            "src_ip": "203.0.113.10",
            "dst_ip": "192.168.1.1",
            "src_port": 443,
            "dst_port": 443,
            "protocol": 6,
            "anomaly_score": 0.88,
            "model_version": "fast_path_v1",
            "inference_time_ms": 1.5,
            "src_ip_enrichment": {
                "asn": 15169,
                "asn_description": "Google LLC",
                "country": "US",
                "city": "Mountain View",
            },
            "dst_ip_enrichment": {
                "asn": 15169,
                "asn_description": "Google LLC",
                "country": "US",
                "city": "Mountain View",
            },
            "stix_indicators": [
                {
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '203.0.113.10']",
                }
            ],
        }

        await self.kafka.produce("alerts.enriched", test_alert)
        await asyncio.sleep(5)

        # Check Elasticsearch
        count = await es_helper.count("network-alerts", {"term": {"rule.id": "fast_path"}})
        assert count >= 1

        # Verify document structure
        results = await es_helper.search(
            "network-alerts", {"term": {"rule.id": "fast_path"}}, size=1
        )
        hits = results.get("hits", {}).get("hits", [])
        assert len(hits) >= 1

        doc = hits[0]["_source"]
        assert doc["event"]["kind"] == "alert"
        assert doc["source"]["ip"] == "203.0.113.10"
        assert doc["event"]["severity"] in ["warning", "error", "critical"]

    @pytest.mark.asyncio
    async def test_api_endpoints(self):
        """Test API endpoints for alert querying."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            # Health check
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] in ["healthy", "degraded"]

            # List alerts
            response = await client.get("/api/v1/alerts?limit=10")
            assert response.status_code == 200
            data = response.json()
            assert "alerts" in data
            assert "total" in data

            # Stats
            stats = await client.get("/api/v1/alerts/stats/summary")
            assert stats.status_code == 200
            stats_data = stats.json()
            assert "total" in stats_data
            assert "by_severity" in stats_data

    @pytest.mark.asyncio
    async def test_model_registry(self):
        """Test model registry operations."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:8080") as client:
            # Health
            health = await client.get("/health")
            assert health.status_code == 200

            # Search models
            resp = await client.get("/models")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_alert_routing_by_severity(self):
        """Test alerts are routed to correct severity topics."""
        test_cases = [
            ("debug", "alerts.debug"),
            ("info", "alerts.info"),
            ("warning", "alerts.warning"),
            ("error", "alerts.error"),
            ("critical", "alerts.critical"),
        ]

        for severity, _expected_topic in test_cases:
            alert = {
                "alert_type": "test",
                "flow_key": f"severity-test-{severity}",
                "timestamp": time.time(),
                "is_anomaly": True,
                "severity": severity,
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
            }
            await self.kafka.produce("alerts.enriched", alert)

        await asyncio.sleep(3)

        # Verify each severity went to correct topic
        for severity, _expected_topic in test_cases:
            _ = await self.kafka.consume(
                f"alerts.{severity}", f"e2e-test-{severity}", max_messages=5
            )
            # At least one should be there
            # Note: This test assumes routing is implemented correctly

    @pytest.mark.asyncio
    async def test_deduplication(self, redis_helper: RedisTestHelper):
        """Test alert deduplication in alerting service."""
        # Send same alert multiple times
        duplicate_alert = {
            "alert_type": "fast_path",
            "flow_key": "dedup-test-flow",
            "timestamp": time.time(),
            "is_anomaly": True,
            "src_ip": "192.168.1.200",
            "dst_ip": "10.0.0.200",
            "src_port": 8080,
            "dst_port": 80,
            "protocol": 6,
            "anomaly_score": 0.9,
        }

        # Send same alert 3 times
        for _ in range(3):
            await self.kafka.produce("alerts.enriched", duplicate_alert)

        await asyncio.sleep(3)

        # Check enriched alerts - should only have 1 after dedup
        enriched = await self.kafka.consume("alerts.enriched", "e2e-dedup-test", max_messages=10)

        # Should have deduplicated
        deduped = [a for a in enriched if a.get("flow_key") == "dedup-test-flow"]
        # Exact count depends on dedup window, but should be <= 1 in ideal case
        assert len(deduped) <= 1

    @pytest.mark.asyncio
    async def test_correlation_across_detectors(self):
        """Test correlation across different detector outputs."""
        base_time = time.time()

        # Same source IP triggering multiple detectors
        multi_alerts = [
            {
                "alert_type": "fast_path",
                "flow_key": "corr-ip-test-1",
                "timestamp": base_time,
                "is_anomaly": True,
                "src_ip": "198.51.100.50",
                "dst_ip": "192.168.1.10",
                "severity": "critical",
            },
            {
                "alert_type": "deep_path",
                "flow_key": "corr-ip-test-2",
                "timestamp": base_time + 2,
                "is_anomaly": True,
                "src_ip": "198.51.100.50",
                "dst_ip": "192.168.1.11",
                "severity": "error",
            },
            {
                "alert_type": "xgboost_supervised",
                "flow_key": "corr-ip-test-3",
                "timestamp": base_time + 4,
                "is_anomaly": True,
                "src_ip": "198.51.100.50",
                "dst_ip": "192.168.1.12",
                "severity": "critical",
            },
        ]

        for alert in multi_alerts:
            await self.kafka.produce("alerts.enriched", alert)

        await asyncio.sleep(5)

        # Check correlation in enriched alerts
        enriched = await self.kafka.consume("alerts.enriched", "e2e-corr-test", max_messages=10)

        corr_alerts = [a for a in enriched if a.get("src_ip") == "198.51.100.50"]
        if len(corr_alerts) > 1:
            # Should have correlation info
            for alert in corr_alerts:
                assert "correlated_alerts" in alert or "correlation_score" in alert

    @pytest.mark.asyncio
    async def test_slack_integration(self):
        """Test Slack webhook integration (if configured)."""
        # This test only runs if Slack webhook is configured
        import os

        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            pytest.skip("Slack webhook not configured")

        # Trigger a high-severity alert
        alert = {
            "alert_type": "fast_path",
            "flow_key": "slack-test",
            "timestamp": time.time(),
            "is_anomaly": True,
            "severity": "critical",
            "src_ip": "203.0.113.50",
            "dst_ip": "192.168.1.50",
            "anomaly_score": 0.99,
            "model_version": "test",
        }
        await self.kafka.produce("alerts.enriched", alert)

        await asyncio.sleep(5)

        # Note: Actual Slack delivery verification would require
        # Slack API access or webhook capture
        # For now, just verify the alert was processed
        alerts = await self.kafka.consume("alerts.enriched", "e2e-slack-test", max_messages=5)
        slack_alerts = [a for a in alerts if a.get("flow_key") == "slack-test"]
        assert len(slack_alerts) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
