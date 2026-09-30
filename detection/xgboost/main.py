"""XGBoost Supervised Detection Service - Labeled anomaly detection.

The XGBoost detector is a supervised binary classifier trained on labeled
normal/anomalous flows. It consumes features.flows and produces alerts.xgboost.
Training is an offline command (`train`); the default `serve` mode runs inference.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    FEATURE_NAMES,
    XGBoostInferenceResult,
    flow_to_vector,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    input_topic: str = Field(default="features.flows", alias="INPUT_TOPIC")
    output_topic: str = Field(default="alerts.xgboost", alias="OUTPUT_TOPIC")
    consumer_group: str = Field(default="xgboost", alias="CONSUMER_GROUP")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Model
    model_path: str = Field(default="/models/xgboost", alias="MODEL_PATH")
    model_name: str = Field(default="xgboost_anomaly.json", alias="MODEL_NAME")
    anomaly_threshold: float = Field(default=0.5, alias="ANOMALY_THRESHOLD")

    # Training input
    train_input: str = Field(default="/data/labeled_flows.json", alias="TRAIN_INPUT")

    # MLflow
    mlflow_tracking_uri: str = Field(default="http://mlflow:5000", alias="MLFLOW_TRACKING_URI")
    mlflow_experiment_name: str = Field(
        default="xgboost-supervised", alias="MLFLOW_EXPERIMENT_NAME"
    )


@dataclass(slots=True)
class XGBoostDetector:
    settings: Settings
    consumer: AIOKafkaConsumer | None = None
    producer: AIOKafkaProducer | None = None
    running: bool = False

    # Model state
    model: Any = None  # xgboost.Booster
    model_version: str = "unset"
    threshold: float = 0.5
    feature_names: list[str] = cast(list[str], list(FEATURE_NAMES))

    # Metrics
    flows_processed: int = 0
    anomalies_detected: int = 0
    inference_time_total_ms: float = 0.0

    async def start(self) -> None:
        """Initialize Kafka and load model."""
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

        self._load_model()

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        logger.info(
            "Detector stopped",
            flows=self.flows_processed,
            anomalies=self.anomalies_detected,
            avg_inference_ms=self.inference_time_total_ms / max(1, self.flows_processed),
        )

    def _load_model(self) -> None:
        """Load XGBoost model from disk."""
        model_dir = Path(self.settings.model_path)
        model_file = model_dir / self.settings.model_name
        threshold_file = model_dir / "threshold.json"
        version_file = model_dir / "model_version.json"

        if not model_file.exists():
            logger.warning("No model found - detector will not infer", path=str(model_file))
            return

        try:
            import xgboost as xgb  # lazy - heavy, runtime only

            self.model = xgb.Booster()
            self.model.load_model(str(model_file))
            self.model.set_param({"verbosity": 0})
            logger.info("Loaded XGBoost model", path=str(model_file))
        except Exception as exc:
            logger.warning("Model load failed", error=str(exc))
            return

        if threshold_file.exists():
            try:
                data = cast(dict[str, Any], json.loads(threshold_file.read_text()))
                value = data.get("threshold")
                if isinstance(value, (int, float)):
                    self.threshold = float(value)
                    logger.info("Loaded anomaly threshold", threshold=self.threshold)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read threshold.json", error=str(exc))
        else:
            self.threshold = self.settings.anomaly_threshold

        if version_file.exists():
            try:
                data = cast(dict[str, Any], json.loads(version_file.read_text()))
                value = data.get("version")
                if isinstance(value, str):
                    self.model_version = value
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read model_version.json", error=str(exc))

    def _predict(self, vector: list[float]) -> tuple[float, float]:
        """Run inference on a single feature vector.

        Returns (anomaly_probability, inference_time_ms).
        """
        if self.model is None:
            return 0.0, 0.0

        import xgboost as xgb  # lazy - heavy, runtime only

        start = time.perf_counter()
        dmatrix = xgb.DMatrix([vector], feature_names=self.feature_names)
        prob = float(self.model.predict(dmatrix)[0])
        inference_ms = (time.perf_counter() - start) * 1000
        return prob, inference_ms

    async def process_message(self, msg: dict[str, Any]) -> XGBoostInferenceResult | None:
        vector = flow_to_vector(msg)
        if vector is None:
            logger.debug("Skipping flow without a complete feature vector")
            return None

        flow_key_value = msg.get("flow_key")
        flow_key = str(flow_key_value) if flow_key_value is not None else ""
        if not flow_key:
            logger.debug("Skipping flow without flow_key")
            return None

        timestamp_value = msg.get("timestamp")
        timestamp = (
            float(timestamp_value) if isinstance(timestamp_value, (int, float)) else time.time()
        )

        prob, inference_ms = self._predict(vector)
        is_anomaly = prob > self.threshold

        self.flows_processed += 1
        self.inference_time_total_ms += inference_ms
        if is_anomaly:
            self.anomalies_detected += 1

        return XGBoostInferenceResult(
            flow_key=flow_key,
            timestamp=timestamp,
            anomaly_probability=prob,
            is_anomaly=is_anomaly,
            model_version=self.model_version,
            inference_time_ms=inference_ms,
        )

    async def _send_alert(self, result: XGBoostInferenceResult, source: dict[str, Any]) -> None:
        if self.producer is None:
            return
        payload: dict[str, Any] = {
            "alert_type": "xgboost_supervised",
            "flow_key": result.flow_key,
            "timestamp": result.timestamp,
            "is_anomaly": result.is_anomaly,
            "anomaly_probability": result.anomaly_probability,
            "model_version": result.model_version,
            "inference_time_ms": result.inference_time_ms,
            "src_ip": source.get("src_ip"),
            "dst_ip": source.get("dst_ip"),
            "src_port": source.get("src_port"),
            "dst_port": source.get("dst_port"),
            "protocol": source.get("protocol"),
        }
        try:
            await self.producer.send_and_wait(self.settings.output_topic, payload)
            if result.is_anomaly:
                logger.warning(
                    "Detected anomaly", flow_key=result.flow_key, prob=result.anomaly_probability
                )
        except Exception as exc:
            logger.warning("Failed to send alert", error=str(exc))

    async def run(self) -> None:
        """Main processing loop."""
        self.running = True
        logger.info(
            "XGBoost detector started", threshold=self.threshold, model_version=self.model_version
        )
        if self.consumer is None:
            logger.error("Consumer not initialized")
            return
        try:
            async for msg in self.consumer:
                if not self.running:
                    break
                result = await self.process_message(msg.value)
                if result is not None:
                    await self._send_alert(result, msg.value)
                if self.flows_processed % 1000 == 0 and self.flows_processed > 0:
                    avg_ms = self.inference_time_total_ms / self.flows_processed
                    logger.info(
                        "XGBoost stats",
                        flows=self.flows_processed,
                        anomalies=self.anomalies_detected,
                        avg_inference_ms=round(avg_ms, 2),
                    )
        except Exception as exc:
            logger.exception("Processing loop error", error=str(exc))
            raise


@dataclass(slots=True)
class CliArgs:
    command: str = "serve"
    input: str | None = None
    output: str | None = None
    epochs: int | None = None
    threshold: float | None = None


def _parse_args(argv: list[str] | None = None) -> CliArgs:
    parser = argparse.ArgumentParser(
        prog="detection.xgboost.main",
        description="XGBoost supervised anomaly detector (serve | train)",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["serve", "train"],
        default="serve",
        help="serve: consume features and emit alerts (default); train: offline model training",
    )
    parser.add_argument("--input", type=str, default=None, help="training input (JSON)")
    parser.add_argument("--output", type=str, default=None, help="training output directory")
    parser.add_argument("--epochs", type=int, default=None, help="max estimators override")
    parser.add_argument(
        "--threshold", type=float, default=None, help="anomaly probability threshold override"
    )
    raw = vars(parser.parse_args(argv))
    return CliArgs(
        command=cast(str, raw.get("command", "serve")),
        input=cast(str | None, raw.get("input")),
        output=cast(str | None, raw.get("output")),
        epochs=cast(int | None, raw.get("epochs")),
        threshold=cast(float | None, raw.get("threshold")),
    )


def run_training(args: CliArgs) -> int:
    from .train import train_model  # lazy - heavy deps

    settings = Settings()
    input_path = Path(args.input) if args.input else Path(settings.train_input)
    if not input_path.exists():
        logger.error("training input not found", path=str(input_path))
        return 2
    output_dir = Path(args.output) if args.output else Path(settings.model_path)
    n_estimators = args.epochs or 500
    threshold = args.threshold or settings.anomaly_threshold
    try:
        result = train_model(
            input_path=input_path,
            output_dir=output_dir,
            _model_path=str(output_dir),
            model_name=settings.model_name,
            n_estimators=n_estimators,
            threshold=threshold,
            mlflow_tracking_uri=settings.mlflow_tracking_uri,
            mlflow_experiment_name=settings.mlflow_experiment_name,
        )
    except (OSError, ValueError) as exc:
        logger.exception("Training failed", error=str(exc))
        return 1
    logger.info("Training finished", version=result.model_version)
    return 0


async def run_server() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )
    settings = Settings()
    detector = XGBoostDetector(settings)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(detector.stop()))
    await detector.start()
    try:
        await detector.run()
    finally:
        await detector.stop()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "train":
        return run_training(args)
    asyncio.run(run_server())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
