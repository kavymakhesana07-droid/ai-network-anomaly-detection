"""
Fast Path Detection - Domain logic for sub-second anomaly detection.
No external ML dependencies (scikit-learn, onnxruntime) so unit tests run fast.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(slots=True)
class FastPathConfig:
    """Configuration for fast path detection."""

    # Model
    model_path: str = "/models/fast_path"
    use_onnx: bool = True
    onnx_model_name: str = "isolation_forest.onnx"

    # Isolation Forest (fallback when ONNX not available)
    n_estimators: int = 100
    max_samples: int = 256
    contamination: float = 0.1
    random_state: int = 42

    # Inference
    batch_size: int = 100
    score_threshold: float = -0.5  # Isolation Forest anomaly score threshold

    # Redis
    redis_url: str = "redis://redis:6379"
    redis_ttl: int = 3600  # Cache TTL for model weights

    # Sigma rules
    sigma_rules_path: str = "/rules/sigma"


@dataclass(slots=True)
class FlowFeatures:
    """Feature vector for a single flow (matches feature_extraction output)."""

    # Basic flow identifiers
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # Time features
    timestamp: float
    duration: float

    # Volume features
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    fwd_payload_bytes: int
    bwd_payload_bytes: int

    # Packet stats
    fwd_packet_len_max: float
    fwd_packet_len_min: float
    fwd_packet_len_mean: float
    fwd_packet_len_std: float
    bwd_packet_len_max: float
    bwd_packet_len_min: float
    bwd_packet_len_mean: float
    bwd_packet_len_std: float

    # IAT features
    fwd_iat_total: float
    fwd_iat_mean: float
    fwd_iat_std: float
    fwd_iat_max: float
    fwd_iat_min: float
    bwd_iat_total: float
    bwd_iat_mean: float
    bwd_iat_std: float
    bwd_iat_max: float
    bwd_iat_min: float

    # Flags
    fin_flag_count: int
    syn_flag_count: int
    rst_flag_count: int
    psh_flag_count: int
    ack_flag_count: int
    urg_flag_count: int
    cwr_flag_count: int
    ece_flag_count: int

    # Rates
    fwd_packets_per_sec: float
    bwd_packets_per_sec: float
    fwd_bytes_per_sec: float
    bwd_bytes_per_sec: float

    # Subflows
    subflow_fwd_packets: int
    subflow_fwd_bytes: int
    subflow_bwd_packets: int
    subflow_bwd_bytes: int

    # Init windows
    init_fwd_win_bytes: int
    init_bwd_win_bytes: int

    # Active/Idle
    active_mean: float
    active_std: float
    active_max: float
    active_min: float
    idle_mean: float
    idle_std: float
    idle_max: float
    idle_min: float

    def to_vector(self) -> list[float]:
        """Convert to feature vector for ML inference (ordered)."""
        return [
            float(self.duration),
            float(self.fwd_packets),
            float(self.bwd_packets),
            float(self.fwd_bytes),
            float(self.bwd_bytes),
            float(self.fwd_payload_bytes),
            float(self.bwd_payload_bytes),
            self.fwd_packet_len_max,
            self.fwd_packet_len_min,
            self.fwd_packet_len_mean,
            self.fwd_packet_len_std,
            self.bwd_packet_len_max,
            self.bwd_packet_len_min,
            self.bwd_packet_len_mean,
            self.bwd_packet_len_std,
            self.fwd_iat_total,
            self.fwd_iat_mean,
            self.fwd_iat_std,
            self.fwd_iat_max,
            self.fwd_iat_min,
            self.bwd_iat_total,
            self.bwd_iat_mean,
            self.bwd_iat_std,
            self.bwd_iat_max,
            self.bwd_iat_min,
            float(self.fin_flag_count),
            float(self.syn_flag_count),
            float(self.rst_flag_count),
            float(self.psh_flag_count),
            float(self.ack_flag_count),
            float(self.urg_flag_count),
            float(self.cwr_flag_count),
            float(self.ece_flag_count),
            self.fwd_packets_per_sec,
            self.bwd_packets_per_sec,
            self.fwd_bytes_per_sec,
            self.bwd_bytes_per_sec,
            float(self.subflow_fwd_packets),
            float(self.subflow_fwd_bytes),
            float(self.subflow_bwd_packets),
            float(self.subflow_bwd_bytes),
            float(self.init_fwd_win_bytes),
            float(self.init_bwd_win_bytes),
            self.active_mean,
            self.active_std,
            self.active_max,
            self.active_min,
            self.idle_mean,
            self.idle_std,
            self.idle_max,
            self.idle_min,
        ]

    @classmethod
    def feature_names(cls) -> list[str]:
        """Return ordered feature names matching to_vector()."""
        return [
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
        ]


@dataclass(slots=True)
class DetectionResult:
    """Result of fast path detection."""

    flow_key: str
    timestamp: float
    is_anomaly: bool
    anomaly_score: float  # Isolation Forest score (negative = anomaly)
    confidence: float  # 0-1
    model_version: str
    inference_time_ms: float

    # Optional rule match
    rule_id: str | None = None
    rule_name: str | None = None
    rule_severity: str | None = None


def normalize_features(vector: list[float], means: list[float], stds: list[float]) -> list[float]:
    """Normalize feature vector using pre-computed mean/std."""
    return [(v - m) / s if s > 0 else 0.0 for v, m, s in zip(vector, means, stds, strict=True)]


def isolation_forest_score(
    vector: list[float], trees: list[dict], n_estimators: int, max_samples: int
) -> float:
    """
    Compute Isolation Forest anomaly score (pure Python fallback).
    Score close to 1 = anomaly, close to 0 = normal.
    """
    if not trees:
        return 0.5

    # This is a simplified path length calculation
    # Real implementation would use the actual tree structures
    path_lengths = []
    for tree in trees[:n_estimators]:
        path_len = _path_length(vector, tree, 0)
        path_lengths.append(path_len)

    avg_path_len = sum(path_lengths) / len(path_lengths)
    c_factor = 2 * math.log(max_samples - 1) + 0.5772156649 - 2 * (max_samples - 1) / max_samples
    score = 2 ** (-avg_path_len / c_factor) if c_factor != 0 else 0.5
    return score


def _path_length(vector: list[float], tree: dict, depth: int) -> float:
    """Calculate path length in a single isolation tree."""
    if "leaf" in tree:
        return depth + tree.get("size", 1) * 0.5

    split_idx = tree.get("split_idx", 0)
    split_val = tree.get("split_val", 0.0)

    if split_idx >= len(vector):
        return depth

    if vector[split_idx] < split_val:
        return _path_length(vector, tree.get("left", {}), depth + 1)
    else:
        return _path_length(vector, tree.get("right", {}), depth + 1)


def load_normalization_params(model_path: str) -> tuple[list[float], list[float]] | None:
    """Load mean/std normalization parameters from model directory."""
    import json
    from pathlib import Path

    params_file = Path(model_path) / "normalization.json"
    if not params_file.exists():
        return None

    try:
        data = json.loads(params_file.read_text())
        return data["means"], data["stds"]
    except Exception:
        return None


def load_onnx_session(model_path: str) -> None:  # noqa: ARG001 - placeholder signature
    """Load ONNX Runtime inference session (placeholder for actual implementation)."""
    # Actual implementation would use onnxruntime.InferenceSession
    # This is a placeholder for type checking
    return None


def run_onnx_inference(session: object, vector: list[float]) -> float:  # noqa: ARG001 - placeholder signature
    """Run ONNX model inference (placeholder)."""
    # Actual: outputs = session.run(None, {"input": [vector]})  # noqa: ERA001 - illustrative only
    return 0.5
