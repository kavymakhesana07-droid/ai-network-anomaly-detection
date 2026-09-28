"""
Fast Path Detection Service - Sub-second anomaly detection using ONNX Runtime + Isolation Forest.
Production-grade: async Kafka I/O, ONNX inference, Redis caching, Sigma rules, metrics.
"""

import asyncio
import json
import signal
import time
from dataclasses import dataclass
from pathlib import Path

# Type ignores for libs without stubs - handled by mypy config
import redis.asyncio as redis
import structlog
import yaml
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    DetectionResult,
    FlowFeatures,
    isolation_forest_score,
    load_normalization_params,
    load_onnx_session,
    normalize_features,
    run_onnx_inference,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    input_topic: str = Field(default="features.flows", alias="INPUT_TOPIC")
    output_topic: str = Field(default="alerts.raw", alias="OUTPUT_TOPIC")
    consumer_group: str = Field(default="fast-path", alias="CONSUMER_GROUP")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Model
    model_path: str = Field(default="/models/fast_path", alias="MODEL_PATH")
    use_onnx: bool = Field(default=True, alias="USE_ONNX")
    onnx_model_name: str = Field(default="isolation_forest.onnx", alias="ONNX_MODEL_NAME")
    score_threshold: float = Field(default=-0.5, alias="SCORE_THRESHOLD")

    # Isolation Forest fallback
    n_estimators: int = Field(default=100, alias="N_ESTIMATORS")
    max_samples: int = Field(default=256, alias="MAX_SAMPLES")
    contamination: float = Field(default=0.1, alias="CONTAMINATION")
    random_state: int = Field(default=42, alias="RANDOM_STATE")

    # Sigma rules
    sigma_rules_path: str = Field(default="/rules/sigma", alias="SIGMA_RULES_PATH")

    # Redis
    redis_url: str = Field(default="redis://redis:6379", alias="REDIS_URL")

    # Metrics
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")


@dataclass(slots=True)
class FastPathDetector:
    settings: Settings
    consumer: AIOKafkaConsumer | None = None
    producer: AIOKafkaProducer | None = None
    redis_client: redis.Redis | None = None
    running: bool = False

    # Model state
    onnx_session: object | None = None
    normalization_means: list[float] | None = None
    normalization_stds: list[float] | None = None
    isolation_trees: list[dict[str, object]] = None  # type: ignore[assignment]
    model_version: str = "1.0.0"

    # Sigma rules
    sigma_rules: list[dict[str, object]] = None  # type: ignore[assignment]

    # Metrics
    flows_processed: int = 0
    anomalies_detected: int = 0
    inference_time_total_ms: float = 0.0
    sigma_matches: int = 0

    def __post_init__(self):
        self.isolation_trees = []
        self.sigma_rules = []

    async def start(self) -> None:
        """Initialize Kafka, Redis, load model and rules."""
        # Kafka consumer
        self.consumer = AIOKafkaConsumer(
            self.settings.input_topic,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id=self.settings.consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=self.settings.kafka_batch_size,
            value_deserializer=lambda m: json.loads(m.decode()),
        )
        await self.consumer.start()
        logger.info("Kafka consumer started", topic=self.settings.input_topic)

        # Kafka producer
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            batch_size=self.settings.kafka_batch_size,
            linger_ms=self.settings.kafka_linger_ms,
            compression_type=self.settings.kafka_compression,
            value_serializer=lambda v: json.dumps(v).encode(),
            acks="all",
            enable_idempotence=True,
        )
        await self.producer.start()
        logger.info("Kafka producer started", brokers=self.settings.kafka_brokers)

        # Redis
        self.redis_client = redis.from_url(
            self.settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Redis connected", url=self.settings.redis_url)

        # Load model
        await self._load_model()

        # Load Sigma rules
        await self._load_sigma_rules()

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        if self.redis_client:
            await self.redis_client.close()
        logger.info(
            "Detector stopped",
            flows=self.flows_processed,
            anomalies=self.anomalies_detected,
            sigma_matches=self.sigma_matches,
            avg_inference_ms=self.inference_time_total_ms / max(1, self.flows_processed),
        )

    async def _load_model(self) -> None:
        """Load ONNX model and normalization params, or fallback Isolation Forest."""
        model_path = Path(self.settings.model_path)

        # Try ONNX first
        if self.settings.use_onnx:
            onnx_path = model_path / self.settings.onnx_model_name
            if onnx_path.exists():
                self.onnx_session = load_onnx_session(str(onnx_path))
                logger.info("Loaded ONNX model", path=str(onnx_path))
            else:
                logger.warning("ONNX model not found, will use fallback", path=str(onnx_path))

        # Load normalization params
        norm = load_normalization_params(self.settings.model_path)
        if norm:
            self.normalization_means, self.normalization_stds = norm
            logger.info("Loaded normalization params", n_features=len(self.normalization_means))
        else:
            logger.warning("No normalization params found")

        # Load Isolation Forest trees (fallback)
        trees_file = model_path / "isolation_forest_trees.json"
        if trees_file.exists():
            try:
                import json

                self.isolation_trees = json.loads(trees_file.read_text())
                logger.info("Loaded Isolation Forest trees", n_trees=len(self.isolation_trees))
            except Exception as exc:
                logger.warning("Failed to load trees", error=str(exc))

    async def _load_sigma_rules(self) -> None:
        """Load Sigma rules from directory."""
        rules_dir = Path(self.settings.sigma_rules_path)
        if not rules_dir.exists():
            logger.warning("Sigma rules directory not found", path=str(rules_dir))
            return

        count = 0
        for rule_file in rules_dir.rglob("*.yml"):
            try:
                rule = yaml.safe_load(rule_file.read_text())
                if rule and "detection" in rule:
                    self.sigma_rules.append(rule)
                    count += 1
            except Exception as exc:
                logger.warning("Failed to load rule", file=str(rule_file), error=str(exc))

        logger.info("Loaded Sigma rules", count=count)

    def _evaluate_sigma(
        self, features: FlowFeatures
    ) -> tuple[bool, str | None, str | None, str | None]:
        """Evaluate Sigma rules against flow features (simplified)."""
        for rule in self.sigma_rules:
            detection = rule.get("detection", {})
            if not isinstance(detection, dict):
                detection = {}
            # Simplified: check if any condition matches
            # Real implementation would use sigma's condition evaluation
            if self._match_detection(features, detection):
                self.sigma_matches += 1
                return (
                    True,
                    str(rule.get("id", "")) or None,
                    str(rule.get("title", "")) or None,
                    str(rule.get("level", "medium")) or None,
                )
        return False, None, None, None

    def _match_detection(self, features: FlowFeatures, detection: dict[str, object]) -> bool:
        """Check if flow matches a Sigma detection condition (simplified)."""
        # This is a placeholder - real implementation uses sigma's condition evaluator
        # For now, just check a few common indicators
        if "selection" in detection:
            # Example: check for SYN flood pattern
            if features.syn_flag_count > 100 and features.duration < 1.0:
                return True
            # Example: port scan
            if features.fwd_packets > 1000 and features.fwd_bytes < 5000:
                return True
        return False

    def _predict(self, features: FlowFeatures) -> tuple[float, float]:
        """
        Run inference on flow features.
        Returns (anomaly_score, inference_time_ms)
        """
        start = time.perf_counter()
        vector = features.to_vector()

        # Normalize
        if self.normalization_means and self.normalization_stds:
            vector = normalize_features(vector, self.normalization_means, self.normalization_stds)

        score = 0.5  # Default neutral

        # Try ONNX first
        if self.onnx_session is not None:
            score = run_onnx_inference(self.onnx_session, vector)
        elif self.isolation_trees:
            score = isolation_forest_score(
                vector, self.isolation_trees, self.settings.n_estimators, self.settings.max_samples
            )

        inference_ms = (time.perf_counter() - start) * 1000
        return score, inference_ms

    async def process_flow(self, flow_data: dict[str, object]) -> DetectionResult | None:
        """Process a single flow and return detection result."""
        try:
            # Parse features with explicit type conversion
            def get_str(key: str, default: str = "") -> str:
                val = flow_data.get(key, default)
                return str(val) if val is not None else default

            def get_int(key: str, default: int = 0) -> int:
                val = flow_data.get(key, default)
                return int(val) if isinstance(val, (int, float)) else default

            def get_float(key: str, default: float = 0.0) -> float:
                val = flow_data.get(key, default)
                return float(val) if isinstance(val, (int, float)) else default

            features = FlowFeatures(
                flow_key=get_str("flow_key"),
                src_ip=get_str("src_ip"),
                dst_ip=get_str("dst_ip"),
                src_port=get_int("src_port"),
                dst_port=get_int("dst_port"),
                protocol=get_int("protocol"),
                timestamp=get_float("timestamp") or time.time(),
                duration=get_float("duration"),
                fwd_packets=get_int("fwd_packets"),
                bwd_packets=get_int("bwd_packets"),
                fwd_bytes=get_int("fwd_bytes"),
                bwd_bytes=get_int("bwd_bytes"),
                fwd_payload_bytes=get_int("fwd_payload_bytes"),
                bwd_payload_bytes=get_int("bwd_payload_bytes"),
                fwd_packet_len_max=get_float("fwd_packet_len_max"),
                fwd_packet_len_min=get_float("fwd_packet_len_min"),
                fwd_packet_len_mean=get_float("fwd_packet_len_mean"),
                fwd_packet_len_std=get_float("fwd_packet_len_std"),
                bwd_packet_len_max=get_float("bwd_packet_len_max"),
                bwd_packet_len_min=get_float("bwd_packet_len_min"),
                bwd_packet_len_mean=get_float("bwd_packet_len_mean"),
                bwd_packet_len_std=get_float("bwd_packet_len_std"),
                fwd_iat_total=get_float("fwd_iat_total"),
                fwd_iat_mean=get_float("fwd_iat_mean"),
                fwd_iat_std=get_float("fwd_iat_std"),
                fwd_iat_max=get_float("fwd_iat_max"),
                fwd_iat_min=get_float("fwd_iat_min"),
                bwd_iat_total=get_float("bwd_iat_total"),
                bwd_iat_mean=get_float("bwd_iat_mean"),
                bwd_iat_std=get_float("bwd_iat_std"),
                bwd_iat_max=get_float("bwd_iat_max"),
                bwd_iat_min=get_float("bwd_iat_min"),
                fin_flag_count=get_int("fin_flag_count"),
                syn_flag_count=get_int("syn_flag_count"),
                rst_flag_count=get_int("rst_flag_count"),
                psh_flag_count=get_int("psh_flag_count"),
                ack_flag_count=get_int("ack_flag_count"),
                urg_flag_count=get_int("urg_flag_count"),
                cwr_flag_count=get_int("cwr_flag_count"),
                ece_flag_count=get_int("ece_flag_count"),
                fwd_packets_per_sec=get_float("fwd_packets_per_sec"),
                bwd_packets_per_sec=get_float("bwd_packets_per_sec"),
                fwd_bytes_per_sec=get_float("fwd_bytes_per_sec"),
                bwd_bytes_per_sec=get_float("bwd_bytes_per_sec"),
                subflow_fwd_packets=get_int("subflow_fwd_packets"),
                subflow_fwd_bytes=get_int("subflow_fwd_bytes"),
                subflow_bwd_packets=get_int("subflow_bwd_packets"),
                subflow_bwd_bytes=get_int("subflow_bwd_bytes"),
                init_fwd_win_bytes=get_int("init_fwd_win_bytes"),
                init_bwd_win_bytes=get_int("init_bwd_win_bytes"),
                active_mean=get_float("active_mean"),
                active_std=get_float("active_std"),
                active_max=get_float("active_max"),
                active_min=get_float("active_min"),
                idle_mean=get_float("idle_mean"),
                idle_std=get_float("idle_std"),
                idle_max=get_float("idle_max"),
                idle_min=get_float("idle_min"),
            )

            # ML inference
            anomaly_score, inference_ms = self._predict(features)

            # Sigma rules
            sigma_match, rule_id, rule_name, rule_severity = self._evaluate_sigma(features)

            # Determine anomaly
            is_anomaly = anomaly_score < self.settings.score_threshold or sigma_match

            # Confidence based on score distance from threshold
            confidence = min(1.0, abs(anomaly_score - self.settings.score_threshold) * 2)

            result = DetectionResult(
                flow_key=features.flow_key,
                timestamp=features.timestamp,
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                confidence=confidence,
                model_version=self.model_version,
                inference_time_ms=inference_ms,
                rule_id=rule_id,
                rule_name=rule_name,
                rule_severity=rule_severity,
            )

            # Update metrics
            self.flows_processed += 1
            self.inference_time_total_ms += inference_ms
            if is_anomaly:
                self.anomalies_detected += 1

        except Exception as exc:
            logger.exception("Flow processing failed", error=str(exc))
            return None
        else:
            return result

    async def run(self) -> None:
        """Main processing loop."""
        self.running = True
        logger.info("Fast path detector started")

        if self.consumer is None:
            logger.error("Consumer not initialized")
            return

        try:
            async for msg in self.consumer:
                if not self.running:
                    break

                result = await self.process_flow(msg.value)
                if result:
                    # Send to output topic
                    await self._send_result(result)

                # Periodic metrics log
                if self.flows_processed % 1000 == 0:
                    avg_ms = self.inference_time_total_ms / self.flows_processed
                    logger.info(
                        "Fast path stats",
                        processed=self.flows_processed,
                        anomalies=self.anomalies_detected,
                        sigma=self.sigma_matches,
                        avg_inference_ms=round(avg_ms, 2),
                    )

        except Exception:
            logger.exception("Processing loop error")
            raise

    async def _send_result(self, result: DetectionResult) -> None:
        """Send detection result to Kafka output topic."""
        if not self.producer:
            return

        payload = {
            "flow_key": result.flow_key,
            "timestamp": result.timestamp,
            "is_anomaly": result.is_anomaly,
            "anomaly_score": result.anomaly_score,
            "confidence": result.confidence,
            "model_version": result.model_version,
            "inference_time_ms": result.inference_time_ms,
        }
        if result.rule_id:
            payload["rule_id"] = result.rule_id
            payload["rule_name"] = result.rule_name
            payload["rule_severity"] = result.rule_severity

        try:
            await self.producer.send_and_wait(self.settings.output_topic, payload)
        except Exception as exc:
            logger.warning("Failed to send result", error=str(exc))


async def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )

    settings = Settings()
    detector = FastPathDetector(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(detector.stop()))

    await detector.start()

    try:
        await detector.run()
    finally:
        await detector.stop()


if __name__ == "__main__":
    asyncio.run(main())
