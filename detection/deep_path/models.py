"""
Deep Path Detection - Domain logic for LSTM Autoencoder training and inference.
No external ML dependencies (torch, spark) so unit tests run fast.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class DeepPathConfig:
    """Configuration for deep path detection."""

    # Model architecture
    input_dim: int = 51  # Matches FlowFeatures.to_vector() length (NUM_FEATURES)
    hidden_dim: int = 128
    latent_dim: int = 32
    num_layers: int = 2
    dropout: float = 0.2

    # Training
    learning_rate: float = 1e-3
    batch_size: int = 256
    max_epochs: int = 50
    early_stopping_patience: int = 5
    gradient_clip_val: float = 1.0

    # Data
    sequence_length: int = 10  # Number of flow windows per sequence
    train_split: float = 0.8
    val_split: float = 0.1
    test_split: float = 0.1

    # Anomaly threshold (percentile of training reconstruction error)
    anomaly_threshold_percentile: float = 95.0

    # Model paths
    model_path: str = "/models/deep_path"
    checkpoint_path: str = "/models/deep_path/checkpoints"
    onnx_model_name: str = "lstm_ae.onnx"

    # Spark
    spark_master: str = "local[*]"
    spark_app_name: str = "anomaly-detection-deep-path"
    spark_executor_memory: str = "2g"
    spark_driver_memory: str = "2g"

    # MLflow
    mlflow_tracking_uri: str = "http://mlflow:5000"
    mlflow_experiment_name: str = "deep-path-lstm-ae"


@dataclass(slots=True)
class FlowSequence:
    """A sequence of flow feature vectors for LSTM input."""

    flow_keys: list[str]
    sequences: list[list[float]]  # [seq_len, feature_dim]
    timestamps: list[float]
    labels: list[int] | None = None  # 0=normal, 1=anomaly (if labeled)


@dataclass(slots=True)
class TrainingResult:
    """Result of model training."""

    model_version: str
    train_loss: float
    val_loss: float
    test_loss: float
    anomaly_threshold: float
    epochs_trained: int
    training_time_seconds: float
    mlflow_run_id: str | None = None


@dataclass(slots=True)
class InferenceResult:
    """Result of anomaly inference on a flow sequence."""

    flow_key: str
    timestamp: float
    reconstruction_error: float
    anomaly_score: float  # Normalized 0-1
    is_anomaly: bool
    model_version: str
    inference_time_ms: float


# Feature names in the exact order of fast_path FlowFeatures.to_vector().
# Keeping this as an explicit tuple (rather than a dict) means the order IS the
# contract: index i in this tuple is feature i in the vector.
FEATURE_NAMES: tuple[str, ...] = (
    "duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_payload_bytes",
    "bwd_payload_bytes",
    "fwd_packet_len_max",
    "fwd_packet_len_min",
    "fwd_packet_len_mean",
    "fwd_packet_len_std",
    "bwd_packet_len_max",
    "bwd_packet_len_min",
    "bwd_packet_len_mean",
    "bwd_packet_len_std",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwr_flag_count",
    "ece_flag_count",
    "fwd_packets_per_sec",
    "bwd_packets_per_sec",
    "fwd_bytes_per_sec",
    "bwd_bytes_per_sec",
    "subflow_fwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_packets",
    "subflow_bwd_bytes",
    "init_fwd_win_bytes",
    "init_bwd_win_bytes",
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min",
)

FEATURE_INDICES: dict[str, int] = {name: idx for idx, name in enumerate(FEATURE_NAMES)}

NUM_FEATURES = len(FEATURE_NAMES)


def get_feature_indices() -> dict[str, int]:
    """Return mapping of feature name to index."""
    return FEATURE_INDICES.copy()


def select_features(vector: list[float], feature_names: list[str]) -> list[float]:
    """Select subset of features by name."""
    indices = [FEATURE_INDICES[name] for name in feature_names if name in FEATURE_INDICES]
    return [vector[i] for i in indices]


def normalize_sequence(
    sequence: list[list[float]], means: list[float], stds: list[float]
) -> list[list[float]]:
    """Normalize a sequence of feature vectors."""
    return [
        [(v - m) / s if s > 0 else 0.0 for v, m, s in zip(vec, means, stds, strict=True)]
        for vec in sequence
    ]


def create_sequences(
    flows: list[dict[str, Any]], sequence_length: int, stride: int = 1
) -> list[FlowSequence]:
    """
    Group flows into sequences for LSTM training.
    Groups by flow_key (5-tuple) and creates sliding windows.
    """
    from collections import defaultdict

    # Group flows by flow_key
    grouped = defaultdict(list)
    for flow in flows:
        key = flow.get("flow_key", "")
        if key:
            grouped[key].append(flow)

    sequences = []
    for flow_key, flow_list in grouped.items():
        # Sort by timestamp
        flow_list.sort(key=lambda f: f.get("timestamp", 0.0))

        # Create sliding windows
        for i in range(0, len(flow_list) - sequence_length + 1, stride):
            window = flow_list[i : i + sequence_length]
            seq_data = [f.get("features", []) for f in window]
            timestamps = [f.get("timestamp", 0.0) for f in window]

            if all(len(s) == NUM_FEATURES for s in seq_data):
                sequences.append(
                    FlowSequence(
                        flow_keys=[flow_key] * sequence_length,
                        sequences=seq_data,
                        timestamps=timestamps,
                    )
                )

    return sequences


def split_data(
    sequences: list[FlowSequence], train_split: float, val_split: float, _test_split: float
) -> tuple[list[FlowSequence], list[FlowSequence], list[FlowSequence]]:
    """Split sequences into train/val/test sets deterministically.

    The split uses the sequence's (flow_key, first_timestamp) as a stable sort key
    and then assigns each sequence to a bucket proportional to its position in the
    sorted order. This avoids the temporal leak of a contiguous slice while keeping
    the split reproducible without any RNG.
    """
    if not sequences:
        return [], [], []

    ordered = sorted(
        sequences,
        key=lambda s: (
            s.flow_keys[0] if s.flow_keys else "",
            s.timestamps[0] if s.timestamps else 0.0,
        ),
    )

    train: list[FlowSequence] = []
    val: list[FlowSequence] = []
    test: list[FlowSequence] = []

    n = len(ordered)
    for i, seq in enumerate(ordered):
        pos = i / (n - 1) if n > 1 else 0.0
        if pos < train_split:
            train.append(seq)
        elif pos < train_split + val_split:
            val.append(seq)
        else:
            test.append(seq)

    return train, val, test


def compute_reconstruction_errors(
    original: list[list[float]], reconstructed: list[list[float]]
) -> list[float]:
    """Compute MSE reconstruction error for each sequence."""
    errors = []
    for orig, recon in zip(original, reconstructed, strict=True):
        mse = sum((o - r) ** 2 for o, r in zip(orig, recon, strict=True)) / len(orig)
        errors.append(mse)
    return errors


def percentile_threshold(errors: list[float], percentile: float) -> float:
    """Compute anomaly threshold at given percentile."""
    if not errors:
        return 0.0
    sorted_errors = sorted(errors)
    idx = int(len(sorted_errors) * percentile / 100)
    return sorted_errors[min(idx, len(sorted_errors) - 1)]


def normalize_anomaly_score(
    error: float, threshold: float, max_error: float | None = None
) -> float:
    """Normalize anomaly score to 0-1 range."""
    if max_error is None or max_error <= threshold:
        return 1.0 if error > threshold else 0.0
    if error <= threshold:
        return 0.0
    return min(1.0, (error - threshold) / (max_error - threshold))
