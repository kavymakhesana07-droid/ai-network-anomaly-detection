"""Offline training for the deep path LSTM autoencoder.

Entry point: python -m detection.deep_path.main train --flows x.json --output DIR

The heavy ML imports (torch, lightning, mlflow, onnx, pyspark) are loaded
lazily inside the functions that need them, so importing this module stays
cheap and the unit tests never touch the ML stack.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast

import structlog

from .models import (
    FEATURE_NAMES,
    NUM_FEATURES,
    FlowSequence,
    TrainingResult,
    create_sequences,
    percentile_threshold,
    split_data,
)

logger = structlog.get_logger(__name__)


def flows_to_vectors(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert feature dicts to ordered vectors so create_sequences can use them."""
    converted: list[dict[str, Any]] = []
    for flow in flows:
        features = flow.get("features")
        if not isinstance(features, dict):
            continue
        vector: list[float] = []
        ok = True
        for name in FEATURE_NAMES:
            value = features.get(name)
            if value is None:
                ok = False
                break
            try:
                vector.append(float(value))
            except (TypeError, ValueError):
                ok = False
                break
        if ok and len(vector) == NUM_FEATURES:
            converted.append({**flow, "features": vector})
    return converted


def compute_normalization(
    sequences: list[FlowSequence],
) -> tuple[list[float], list[float]]:
    """Mean and std per feature across every vector in the training set."""
    sums = [0.0] * NUM_FEATURES
    sumsq = [0.0] * NUM_FEATURES
    count = 0
    for seq in sequences:
        for vector in seq.sequences:
            for i, value in enumerate(vector):
                sums[i] += value
                sumsq[i] += value * value
            count += 1
    if count == 0:
        return [0.0] * NUM_FEATURES, [1.0] * NUM_FEATURES
    means = [s / count for s in sums]
    stds = [
        (sumsq[i] / count - means[i] * means[i])
        if sumsq[i] / count - means[i] * means[i] > 0.0
        else 1.0
        for i in range(NUM_FEATURES)
    ]
    return means, stds


def read_flows(path: Path, spark_master: str, spark_app: str) -> list[dict[str, Any]]:
    """Read training flows from JSON or parquet."""
    if path.suffix.lower() == ".parquet":
        return _read_parquet(path, spark_master, spark_app)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        msg = f"{path} must contain a JSON list of flows"
        raise TypeError(msg)
    return cast(list[dict[str, Any]], data)


def _read_parquet(path: Path, spark_master: str, spark_app: str) -> list[dict[str, Any]]:
    from pyspark.sql import SparkSession  # lazy - heavy, runtime only

    spark = (
        SparkSession.builder
        .master(spark_master)
        .appName(spark_app)
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    try:
        frame = spark.read.parquet(str(path))
        return [cast(dict[str, Any], row.asDict()) for row in frame.collect()]
    finally:
        spark.stop()


def mean_split_error(model: Any, data_loader: Any) -> float:
    """Mean per-sequence reconstruction error over a DataLoader."""
    import torch  # lazy - heavy, runtime only

    total = 0.0
    count = 0
    with torch.no_grad():
        for batch in data_loader:
            recon = model(batch)
            per_sample = ((recon - batch) ** 2).mean(dim=(1, 2))
            total += float(per_sample.sum().item())
            count += per_sample.size(0)
    return total / max(1, count)


def train_model(
    flows_path: Path,
    output_dir: Path,
    model_path: str,
    sequence_length: int,
    max_epochs: int,
    spark_master: str,
    spark_app: str,
    mlflow_tracking_uri: str | None = None,
    mlflow_experiment_name: str = "deep-path-lstm-ae",
) -> TrainingResult:
    from .model import LstmAutoencoder, LstmSeqDataset, seq_collate
    from .models import DeepPathConfig

    started = time.monotonic()

    flows = flows_to_vectors(read_flows(flows_path, spark_master, spark_app))
    logger.info("Flows with complete feature vectors", count=len(flows))

    sequences = create_sequences(flows, sequence_length)
    if len(sequences) < 20:
        msg = f"too few sequences for training: {len(sequences)}"
        raise ValueError(msg)
    train, val, test = split_data(sequences, 0.8, 0.1, 0.1)
    logger.info("Split sequences", train=len(train), val=len(val), test=len(test))

    means, stds = compute_normalization(train)

    config = DeepPathConfig(
        input_dim=NUM_FEATURES,
        sequence_length=sequence_length,
        model_path=model_path,
        max_epochs=max_epochs,
    )
    model = LstmAutoencoder(config)

    import lightning as pl  # lazy - heavy, runtime only
    import torch  # lazy - heavy, runtime only
    from torch.utils.data import DataLoader

    train_loader = DataLoader(
        LstmSeqDataset(train),
        batch_size=config.batch_size,
        shuffle=True,
        collate_fn=seq_collate,
    )
    val_loader = DataLoader(
        LstmSeqDataset(val),
        batch_size=config.batch_size,
        shuffle=False,
        collate_fn=seq_collate,
    )
    test_loader = DataLoader(
        LstmSeqDataset(test),
        batch_size=config.batch_size,
        shuffle=False,
        collate_fn=seq_collate,
    )

    callbacks: list[Any] = []
    if config.early_stopping_patience > 0:
        from lightning.pytorch.callbacks import EarlyStopping

        callbacks.append(
            EarlyStopping(
                monitor="val_loss",
                patience=config.early_stopping_patience,
                mode="min",
            )
        )

    trainer = pl.Trainer(
        max_epochs=config.max_epochs,
        accelerator="auto",
        devices="auto",
        callbacks=callbacks,
        log_every_n_steps=10,
    )
    trainer.fit(model, train_loader, val_loader)

    epochs_trained = config.max_epochs
    train_loss = mean_split_error(model, train_loader)
    val_loss = mean_split_error(model, val_loader)
    test_loss = mean_split_error(model, test_loader)

    # The anomaly threshold is the configured percentile of validation-set
    # reconstruction error, so it is calibrated on held-out data.
    threshold_errors: list[float] = []
    with torch.no_grad():
        for batch in val_loader:
            recon = model(batch)
            per_sample = ((recon - batch) ** 2).mean(dim=(1, 2))
            threshold_errors.extend(float(e) for e in per_sample.tolist())
    threshold = percentile_threshold(threshold_errors, config.anomaly_threshold_percentile)

    version = time.strftime("%Y%m%d-%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    pt_path = output_dir / "lstm_ae.pt"
    torch.save(model.state_dict(), pt_path)
    logger.info("Saved checkpoint", path=str(pt_path))

    onnx_path = output_dir / "lstm_ae.onnx"
    dummy = torch.randn(1, sequence_length, NUM_FEATURES)
    torch.onnx.export(
        model,
        dummy,
        str(onnx_path),
        input_names=["input"],
        output_names=["reconstruction"],
        dynamic_axes={
            "input": {0: "batch", 1: "seq"},
            "reconstruction": {0: "batch", 1: "seq"},
        },
        opset_version=17,
    )
    logger.info("Exported ONNX model", path=str(onnx_path))

    (output_dir / "threshold.json").write_text(
        json.dumps(
            {
                "threshold": threshold,
                "percentile": config.anomaly_threshold_percentile,
                "sequences": len(sequences),
            },
            indent=2,
        )
    )
    (output_dir / "normalization.json").write_text(
        json.dumps({"means": means, "stds": stds}, indent=2)
    )
    (output_dir / "model_version.json").write_text(
        json.dumps(
            {
                "version": version,
                "features": NUM_FEATURES,
                "sequence_length": sequence_length,
                "architecture": "lstm_autoencoder",
            },
            indent=2,
        )
    )

    mlflow_run_id: str | None = None
    if mlflow_tracking_uri:
        try:
            import mlflow  # lazy - heavy, runtime only

            mlflow.set_tracking_uri(mlflow_tracking_uri)
            mlflow.set_experiment(mlflow_experiment_name)
            with mlflow.start_run() as run:
                mlflow.log_params({
                    "input_dim": config.input_dim,
                    "hidden_dim": config.hidden_dim,
                    "latent_dim": config.latent_dim,
                    "num_layers": config.num_layers,
                    "dropout": config.dropout,
                    "learning_rate": config.learning_rate,
                    "batch_size": config.batch_size,
                    "max_epochs": config.max_epochs,
                    "sequence_length": sequence_length,
                    "threshold_percentile": (config.anomaly_threshold_percentile),
                })
                mlflow.log_metrics({
                    "train_loss": train_loss,
                    "val_loss": val_loss,
                    "test_loss": test_loss,
                    "threshold": threshold,
                    "sequences": len(sequences),
                })
                mlflow.log_artifacts(str(output_dir))
                mlflow_run_id = cast(str, run.info.run_id)
                logger.info("Logged MLflow run", run_id=mlflow_run_id)
        except Exception as exc:
            logger.warning("MLflow logging skipped", error=str(exc))

    elapsed = time.monotonic() - started
    result = TrainingResult(
        model_version=version,
        train_loss=train_loss,
        val_loss=val_loss,
        test_loss=test_loss,
        anomaly_threshold=threshold,
        epochs_trained=epochs_trained,
        training_time_seconds=elapsed,
        mlflow_run_id=mlflow_run_id,
    )
    logger.info(
        "Training complete",
        threshold=threshold,
        version=version,
        sequences=len(sequences),
    )
    return result
