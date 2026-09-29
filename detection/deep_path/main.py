"""Deep Path Detection Service - LSTM autoencoder training and streaming inference.

The deep path is the batch/streaming ML lane. It groups flow feature vectors
into time windows per flow, reconstructs each window with an LSTM autoencoder,
and emits an alert when the reconstruction error exceeds the threshold learned
at training time. Training is an offline command (`train`); the default `serve`
mode consumes features.flows and produces alerts.deep.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    FEATURE_NAMES,
    NUM_FEATURES,
    InferenceResult,
    normalize_anomaly_score,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Kafka
    kafka_brokers: str = Field(default="localhost:9092", alias="KAFKA_BROKERS")
    input_topic: str = Field(default="features.flows", alias="INPUT_TOPIC")
    output_topic: str = Field(default="alerts.deep", alias="OUTPUT_TOPIC")
    consumer_group: str = Field(default="deep-path", alias="CONSUMER_GROUP")
    kafka_batch_size: int = Field(default=16384, alias="KAFKA_BATCH_SIZE")
    kafka_linger_ms: int = Field(default=5, alias="KAFKA_LINGER_MS")
    kafka_compression: str = Field(default="snappy", alias="KAFKA_COMPRESSION")

    # Model
    model_path: str = Field(default="/models/deep_path", alias="MODEL_PATH")
    sequence_length: int = Field(default=10, alias="SEQUENCE_LENGTH")
    anomaly_threshold_override: float | None = Field(default=None, alias="ANOMALY_THRESHOLD")
    checkpoint_name: str = Field(default="lstm_ae.pt", alias="CHECKPOINT_NAME")
    onnx_model_name: str = Field(default="lstm_ae.onnx", alias="ONNX_MODEL_NAME")

    # Spark (batch training on parquet)
    spark_master: str = Field(default="local[*]", alias="SPARK_MASTER")
    spark_app_name: str = Field(default="anomaly-detection-deep-path", alias="SPARK_APP_NAME")

    # Experiment tracking
    mlflow_tracking_uri: str = Field(default="http://mlflow:5000", alias="MLFLOW_TRACKING_URI")
    mlflow_experiment_name: str = Field(default="deep-path-lstm-ae", alias="MLFLOW_EXPERIMENT_NAME")


@dataclass(slots=True)
class DeepPathDetector:
    settings: Settings
    consumer: AIOKafkaConsumer | None = None
    producer: AIOKafkaProducer | None = None
    running: bool = False

    # Model state (Any: set by the lazy loader - ONNX session or torch module)
    model: Any = None
    model_kind: str = "none"
    onnx_input_name: str = ""
    threshold: float | None = None
    normalization_means: list[float] | None = None
    normalization_stds: list[float] | None = None
    model_version: str = "unset"

    # Per-flow sliding windows of the last `sequence_length` feature vectors.
    buffers: dict[str, deque[tuple[float, list[float]]]] = field(default_factory=dict)

    # Metrics
    sequences_processed: int = 0
    anomalies_detected: int = 0
    inference_time_total_ms: float = 0.0

    async def start(self) -> None:
        """Initialize Kafka, load artifacts and model."""
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

        self._load_artifacts()
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
            windows=self.sequences_processed,
            anomalies=self.anomalies_detected,
            avg_inference_ms=self.inference_time_total_ms / max(1, self.sequences_processed),
        )

    def _load_artifacts(self) -> None:
        model_dir = Path(self.settings.model_path)

        threshold_file = model_dir / "threshold.json"
        if threshold_file.exists():
            try:
                data = cast(dict[str, Any], json.loads(threshold_file.read_text()))
                value = data.get("threshold")
                if isinstance(value, (int, float)):
                    self.threshold = float(value)
                    logger.info("Loaded anomaly threshold", threshold=self.threshold)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read threshold.json", error=str(exc))

        norm_file = model_dir / "normalization.json"
        if norm_file.exists():
            try:
                data = cast(dict[str, Any], json.loads(norm_file.read_text()))
                means_raw = data.get("means")
                stds_raw = data.get("stds")
                if (
                    isinstance(means_raw, list)
                    and isinstance(stds_raw, list)
                    and len(means_raw) == NUM_FEATURES
                    and len(stds_raw) == NUM_FEATURES
                ):
                    means = [float(v) for v in means_raw]
                    stds = [float(v) for v in stds_raw]
                    self.normalization_means = means
                    self.normalization_stds = stds
                    logger.info("Loaded normalization params", n_features=NUM_FEATURES)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read normalization.json", error=str(exc))

        version_file = model_dir / "model_version.json"
        if version_file.exists():
            try:
                data = cast(dict[str, Any], json.loads(version_file.read_text()))
                value = data.get("version")
                if isinstance(value, str):
                    self.model_version = value
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read model_version.json", error=str(exc))

        if self.settings.anomaly_threshold_override is not None:
            self.threshold = self.settings.anomaly_threshold_override

    def _load_model(self) -> None:
        model_dir = Path(self.settings.model_path)
        if self._try_load_onnx(model_dir):
            return
        if self._try_load_torch(model_dir):
            return
        logger.warning("No model found - detector will buffer but not infer")

    def _try_load_onnx(self, model_dir: Path) -> bool:
        onnx_path = model_dir / self.settings.onnx_model_name
        if not onnx_path.exists():
            return False
        try:
            import onnxruntime as ort  # lazy - heavy, runtime only

            self.model = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
            self.onnx_input_name = self.model.get_inputs()[0].name
        except Exception as exc:
            logger.warning("ONNX load failed, trying torch", error=str(exc))
            return False
        self.model_kind = "onnx"
        logger.info("Loaded ONNX model", path=str(onnx_path))
        return True

    def _try_load_torch(self, model_dir: Path) -> bool:
        ckpt_path = model_dir / self.settings.checkpoint_name
        if not ckpt_path.exists():
            return False
        try:
            import torch  # lazy - heavy, runtime only

            from .model import LstmAutoencoder
            from .models import DeepPathConfig

            config = DeepPathConfig(
                input_dim=NUM_FEATURES,
                sequence_length=self.settings.sequence_length,
            )
            model = LstmAutoencoder(config)
            # weights_only: the checkpoint holds a plain state_dict (no pickled
            # code), so refuse arbitrary unpickling from untrusted model dirs.
            state = torch.load(ckpt_path, map_location="cpu", weights_only=True)
            model.load_state_dict(state)
            model.eval()
            self.model = model
        except Exception as exc:
            logger.warning("Torch checkpoint load failed", error=str(exc))
            return False
        self.model_kind = "torch"
        logger.info("Loaded torch checkpoint", path=str(ckpt_path))
        return True

    def _normalize(self, vector: list[float]) -> list[float]:
        if self.normalization_means and self.normalization_stds:
            return [
                (v - m) / s if s > 0 else 0.0
                for v, m, s in zip(
                    vector,
                    self.normalization_means,
                    self.normalization_stds,
                    strict=True,
                )
            ]
        return vector

    def _reconstruction_error(self, sequence: list[list[float]]) -> float | None:
        """MSE between the window and its autoencoder reconstruction."""
        if self.model_kind == "onnx":
            return self._onnx_error(sequence)
        if self.model_kind == "torch":
            return self._torch_error(sequence)
        return None

    def _onnx_error(self, sequence: list[list[float]]) -> float | None:
        try:
            import numpy as np  # lazy - heavy, runtime only

            arr = np.asarray([sequence], dtype=np.float32)
            outputs = self.model.run(None, {self.onnx_input_name: arr})
            recon = outputs[0]
            diff = arr[0] - recon[0]
            return float(np.mean(diff * diff))
        except Exception as exc:
            logger.warning("ONNX inference failed", error=str(exc))
            return None

    def _torch_error(self, sequence: list[list[float]]) -> float | None:
        try:
            import torch  # lazy - heavy, runtime only

            x = torch.tensor([sequence], dtype=torch.float32)
            with torch.no_grad():
                recon = self.model(x)
                err = torch.nn.functional.mse_loss(recon, x)
            return float(err.item())
        except Exception as exc:
            logger.warning("Torch inference failed", error=str(exc))
            return None

    def _infer(
        self, flow_key: str, timestamp: float, sequence: list[list[float]]
    ) -> InferenceResult | None:
        if self.model is None or self.threshold is None:
            return None
        start = time.perf_counter()
        error = self._reconstruction_error(sequence)
        inference_ms = (time.perf_counter() - start) * 1000
        if error is None:
            return None
        score = normalize_anomaly_score(error, self.threshold)
        is_anomaly = error > self.threshold
        self.sequences_processed += 1
        self.inference_time_total_ms += inference_ms
        if is_anomaly:
            self.anomalies_detected += 1
        return InferenceResult(
            flow_key=flow_key,
            timestamp=timestamp,
            reconstruction_error=error,
            anomaly_score=score,
            is_anomaly=is_anomaly,
            model_version=self.model_version,
            inference_time_ms=inference_ms,
        )

    async def process_message(self, msg: dict[str, Any]) -> InferenceResult | None:
        vector = features_from_message(msg)
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

        window = self.buffers.setdefault(flow_key, deque(maxlen=self.settings.sequence_length))
        window.append((timestamp, self._normalize(vector)))
        if len(window) < self.settings.sequence_length:
            return None

        sequence = [v for _, v in window]
        window.clear()
        return self._infer(flow_key, timestamp, sequence)

    async def _send_alert(self, result: InferenceResult, source: dict[str, Any]) -> None:
        if self.producer is None:
            return
        payload: dict[str, Any] = {
            "alert_type": "deep_path_lstm_ae",
            "flow_key": result.flow_key,
            "timestamp": result.timestamp,
            "is_anomaly": result.is_anomaly,
            "reconstruction_error": result.reconstruction_error,
            "anomaly_score": result.anomaly_score,
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
                    "Detected anomaly",
                    flow_key=result.flow_key,
                    error=result.reconstruction_error,
                )
        except Exception as exc:
            logger.warning("Failed to send alert", error=str(exc))

    async def run(self) -> None:
        """Main processing loop."""
        self.running = True
        logger.info(
            "Deep path detector started",
            model=self.model_kind,
            threshold=self.threshold,
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
                if self.sequences_processed % 500 == 0 and self.sequences_processed > 0:
                    avg_ms = self.inference_time_total_ms / self.sequences_processed
                    logger.info(
                        "Deep path stats",
                        windows=self.sequences_processed,
                        anomalies=self.anomalies_detected,
                        avg_inference_ms=round(avg_ms, 2),
                    )
        except Exception as exc:
            logger.exception("Processing loop error", error=str(exc))
            raise


def features_from_message(msg: dict[str, Any]) -> list[float] | None:
    """Extract the ordered NFV feature vector from a features.flows message.

    Accepts both {"features": {name: value}} and a flat {name: value} message.
    Returns None when a required feature is missing or non-numeric.
    """
    container = msg.get("features")
    if not isinstance(container, dict):
        container = msg
    vector: list[float] = []
    for name in FEATURE_NAMES:
        value = container.get(name)
        if value is None:
            return None
        try:
            vector.append(float(value))
        except (TypeError, ValueError):
            return None
    return vector


@dataclass(slots=True)
class CliArgs:
    command: str = "serve"
    flows: str | None = None
    output: str | None = None
    epochs: int | None = None
    sequence_length: int | None = None


def _parse_args(argv: list[str] | None = None) -> CliArgs:
    parser = argparse.ArgumentParser(
        prog="detection.deep_path.main",
        description="Deep path LSTM autoencoder detector (serve | train)",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["serve", "train"],
        default="serve",
        help="serve: consume features and emit alerts (default); train: offline",
    )
    parser.add_argument("--flows", type=str, default=None, help="training input (JSON or parquet)")
    parser.add_argument("--output", type=str, default=None, help="training output directory")
    parser.add_argument("--epochs", type=int, default=None, help="max epoch override")
    parser.add_argument("--sequence-length", type=int, default=None, help="window length override")
    raw = vars(parser.parse_args(argv))
    return CliArgs(
        command=cast(str, raw.get("command", "serve")),
        flows=cast(str | None, raw.get("flows")),
        output=cast(str | None, raw.get("output")),
        epochs=cast(int | None, raw.get("epochs")),
        sequence_length=cast(int | None, raw.get("sequence_length")),
    )


def run_training(args: CliArgs) -> int:
    from .train import train_model  # lazy - heavy deps

    settings = Settings()
    if not args.flows:
        logger.error("train requires --flows")
        return 2
    flows_path = Path(args.flows)
    if not flows_path.exists():
        logger.error("flows file not found", path=str(flows_path))
        return 2
    output_dir = Path(args.output) if args.output else Path(settings.model_path)
    sequence_length = args.sequence_length or settings.sequence_length
    max_epochs = args.epochs or 20
    try:
        result = train_model(
            flows_path=flows_path,
            output_dir=output_dir,
            model_path=str(output_dir),
            sequence_length=sequence_length,
            max_epochs=max_epochs,
            spark_master=settings.spark_master,
            spark_app=settings.spark_app_name,
            mlflow_tracking_uri=settings.mlflow_tracking_uri,
            mlflow_experiment_name=settings.mlflow_experiment_name,
        )
    except (OSError, TypeError, ValueError) as exc:
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
    detector = DeepPathDetector(settings)
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
