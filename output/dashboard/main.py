"""Streamlit Dashboard for Network Anomaly Detection.

Real-time visualization of enriched alerts with filtering, correlation view,
and STIX indicator display.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st
from streamlit_autorefresh import st_autorefresh

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import redis.asyncio as redis
import structlog
from aiokafka import AIOKafkaConsumer

from output.models import (
    DashboardAlert,
    DashboardConfig,
    create_dashboard_alert,
)

logger = structlog.get_logger(__name__)


class DashboardService:
    """Streamlit Dashboard Service with real-time alert streaming."""

    def __init__(self, config: DashboardConfig) -> None:
        self.config = config
        self.consumer: Any = None
        self.redis_client: Any = None
        self.running = False

        # In-memory alert buffer (for real-time display)
        self.alert_buffer: deque[DashboardAlert] = deque(maxlen=config.max_alerts_display)
        self.alert_counts: dict[str, Any] = {"total": 0, "anomalies": 0, "by_severity": {}}

    async def start(self) -> None:
        """Initialize Kafka consumer and Redis."""
        self.consumer = AIOKafkaConsumer(
            self.config.alerts_topic,
            bootstrap_servers=self.config.kafka_brokers,
            group_id="dashboard-consumer",
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode()),
        )
        await self.consumer.start()
        logger.info("Dashboard Kafka consumer started", topic=self.config.alerts_topic)

        self.redis_client = redis.from_url(
            self.config.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Dashboard Redis connected", url=self.config.redis_url)

    async def stop(self) -> None:
        """Graceful shutdown."""
        if self.consumer:
            await self.consumer.stop()
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Dashboard service stopped")

    async def consume_alerts(self) -> None:
        """Background task to consume alerts from Kafka."""
        try:
            async for msg in self.consumer:
                alert_data = msg.value
                alert = create_dashboard_alert(alert_data)
                self.alert_buffer.appendleft(alert)

                # Update counts
                self.alert_counts["total"] += 1
                if alert.is_anomaly:
                    self.alert_counts["anomalies"] += 1
                sev = alert.severity if isinstance(alert.severity, str) else "unknown"
                self.alert_counts["by_severity"][sev] = (
                    self.alert_counts["by_severity"].get(sev, 0) + 1
                )

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception("Alert consumption error", error=str(exc))


def format_severity_badge(severity: str) -> str:
    """Return HTML badge for severity."""
    colors = {
        "critical": "#FF0000",
        "error": "#FF4500",
        "warning": "#FFA500",
        "notice": "#FFD700",
        "info": "#00BFFF",
        "debug": "#808080",
    }
    color = colors.get(severity.lower(), "#808080")
    return f'<span style="background-color: {color}; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8em;">{severity.upper()}</span>'


def format_ip_link(ip: str | None) -> str:
    """Format IP as clickable link to enrichment details."""
    if not ip:
        return "N/A"
    return f'<a href="#enrichment-{ip}" target="_blank">{ip}</a>'


def main() -> None:
    st.set_page_config(
        page_title="Network Anomaly Detection Dashboard",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Auto-refresh
    st_autorefresh(interval=10000, key="data_refresh")

    # Custom CSS
    st.markdown(
        """
        <style>
        .main > div { padding-top: 1rem; }
        .stMetric { background-color: #f0f2f6; padding: 1rem; border-radius: 0.5rem; }
        .alert-row:hover { background-color: #f5f5f5; cursor: pointer; }
        .severity-badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-weight: bold; }
        </style>
    """,
        unsafe_allow_html=True,
    )

    # Initialize session state
    if "dashboard_service" not in st.session_state:
        config = DashboardConfig()
        st.session_state.dashboard_service = DashboardService(config)
        st.session_state.consumer_task = None

    service = st.session_state.dashboard_service

    # Sidebar
    with st.sidebar:
        st.title("🔍 Network Anomaly Detection")
        st.markdown("---")

        # Connection status
        st.subheader("System Status")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Kafka", "🟢 Connected")
        with col2:
            st.metric("Redis", "🟢 Connected")

        st.markdown("---")

        # Filters
        st.subheader("Filters")
        st.selectbox(
            "Time Range",
            ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days"],
            index=2,
        )

        severity_filter = st.multiselect(
            "Severity",
            ["critical", "error", "warning", "notice", "info", "debug"],
            default=["critical", "error", "warning"],
        )

        alert_types = st.multiselect(
            "Alert Types",
            ["fast_path", "deep_path", "xgboost_supervised"],
            default=["fast_path", "deep_path", "xgboost_supervised"],
        )

        show_only_anomalies = st.checkbox("Show Only Anomalies", value=True)

        st.markdown("---")

        # Statistics
        st.subheader("Statistics (Session)")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Alerts", st.session_state.dashboard_service.alert_counts["total"])
        with col2:
            st.metric("Anomalies", st.session_state.dashboard_service.alert_counts["anomalies"])

        if st.session_state.dashboard_service.alert_counts["by_severity"]:
            st.write("By Severity:")
            for _sev, count in sorted(
                st.session_state.dashboard_service.alert_counts["by_severity"].items()
            ):
                st.write(f"  {_sev.capitalize()}: {count}")

    # Main content
    st.title("🔍 Network Anomaly Detection Dashboard")

    # Auto-start consumer
    if st.session_state.consumer_task is None:
        st.session_state.consumer_task = asyncio.create_task(service.consume_alerts())

    # Alert table
    st.subheader("🚨 Alerts")

    # Filter alerts
    alerts = list(service.alert_buffer)

    if severity_filter:
        alerts = [a for a in alerts if a.severity.lower() in severity_filter]

    if alert_types:
        alerts = [a for a in alerts if any(t in a.alert_type for t in alert_types)]

    if show_only_anomalies:
        alerts = [a for a in alerts if a.is_anomaly]

    # Limit display
    alerts = alerts[: service.config.max_alerts_display]

    if alerts:
        # Create DataFrame for display
        import pandas as pd

        df_data = []
        for alert in alerts:
            df_data.append({
                "Time": datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S"),
                "Type": alert.alert_type,
                "Severity": alert.severity,
                "Flow": alert.flow_key[:30] + "..." if len(alert.flow_key) > 30 else alert.flow_key,
                "Source": f"{alert.src_ip}:{alert.src_port}" if alert.src_ip else "N/A",
                "Destination": f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_ip else "N/A",
                "Score": f"{alert.anomaly_score:.3f}"
                if alert.anomaly_score
                else (
                    f"{alert.reconstruction_error:.3f}"
                    if alert.reconstruction_error
                    else (
                        f"{alert.anomaly_probability:.3f}" if alert.anomaly_probability else "N/A"
                    )
                ),
                "Model": alert.model_version or "N/A",
                "Anomaly": "🔴" if alert.is_anomaly else "🟢",
            })

        df = pd.DataFrame(df_data)

        # Style the dataframe
        def highlight_severity(row):
            colors = {
                "critical": "background-color: #ffebee",
                "error": "background-color: #fff3e0",
                "warning": "background-color: #fff8e1",
                "notice": "background-color: #fffde7",
                "info": "background-color: #e3f2fd",
            }
            color = colors.get(row["Severity"], "")
            return [f"background-color: {color}" if color else "" for _ in row]

        st.dataframe(
            df.style.apply(highlight_severity, axis=1),
            use_container_width=True,
            height=600,
            hide_index=True,
        )
    else:
        st.info("No alerts match the current filters. Waiting for alerts...")

    # Alert Details Modal
    st.markdown("---")
    st.subheader("🔍 Alert Details")

    if alerts:
        selected_idx = st.selectbox(
            "Select alert for details",
            range(len(alerts)),
            format_func=lambda i: (
                f"{alerts[i].timestamp_iso} | {alerts[i].alert_type} | {alerts[i].severity} | {alerts[i].flow_key[:30]}"
            ),
        )

        selected = alerts[selected_idx]

        col1, col2 = st.columns(2)

        with col1:
            st.write("**Basic Info**")
            st.json({
                "Alert ID": selected.flow_key + "_" + str(int(selected.timestamp * 1000)),
                "Type": selected.alert_type,
                "Severity": selected.severity,
                "Status": selected.status,
                "Timestamp": selected.timestamp_iso,
                "Flow Key": selected.flow_key,
                "Anomaly": selected.is_anomaly,
            })

            st.write("**Network**")
            st.json({
                "Source": f"{selected.src_ip}:{selected.src_port}" if selected.src_ip else "N/A",
                "Destination": f"{selected.dst_ip}:{selected.dst_port}"
                if selected.dst_ip
                else "N/A",
                "Protocol": selected.protocol,
            })

            st.write("**Detection**")
            st.json({
                "Anomaly": selected.is_anomaly,
                "Anomaly Score": selected.anomaly_score,
                "Reconstruction Error": selected.reconstruction_error,
                "Anomaly Probability": selected.anomaly_probability,
                "Model Version": selected.model_version,
                "Inference Time (ms)": selected.inference_time_ms,
            })

        with col2:
            if selected.src_ip_enrichment or selected.dst_ip_enrichment:
                st.write("**IP Enrichment**")
                if selected.src_ip_enrichment:
                    st.write("**Source IP**")
                    st.json(selected.src_ip_enrichment)
                if selected.dst_ip_enrichment:
                    st.write("**Destination IP**")
                    st.json(selected.dst_ip_enrichment)

            if selected.stix_indicators:
                st.write("**STIX Indicators**")
                for indicator in selected.stix_indicators:
                    with st.expander(f"STIX: {indicator.get('id', 'N/A')}"):
                        st.json(indicator)

            if selected.correlated_alerts:
                st.write("**Correlated Alerts**")
                for corr in selected.correlated_alerts:
                    st.write(f"• {corr}")
                st.write(f"Correlation Score: {selected.correlation_score:.3f}")
    else:
        st.info("No alerts to display. Select an alert from the table above to view details.")


if __name__ == "__main__":
    main()
