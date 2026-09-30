"""
XGBoost Supervised Detection - Domain logic for labeled anomaly detection.

No external ML dependencies (xgboost, pandas) so unit tests run fast.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class XGBoostConfig:
    """Configuration for XGBoost supervised detection."""

    # Model hyperparameters
    n_estimators: int = 500
    max_depth: int = 8
    learning_rate: float = 0.05
    subsample: float = 0.9
    colsample_bytree: float = 0.8
    min_child_weight: int = 3
    reg_alpha: float = 0.1
    reg_lambda: float = 1.0
    objective: str = "binary:logistic"
    eval_metric: str = "auc"
    tree_method: str = "hist"
    random_state: int = 42
    n_jobs: int = -1

    # Training
    early_stopping_rounds: int = 50
    test_size: float = 0.2
    val_size: float = 0.1
    class_weight_balanced: bool = True

    # Inference
    anomaly_threshold: float = 0.5  # probability threshold

    # Model paths
    model_path: str = "/models/xgboost"
    model_name: str = "xgboost_anomaly.json"

    # MLflow
    mlflow_tracking_uri: str = "http://mlflow:5000"
    mlflow_experiment_name: str = "xgboost-supervised"


@dataclass(slots=True)
class XGBoostTrainingResult:
    """Result of XGBoost model training."""

    model_version: str
    train_auc: float
    val_auc: float
    test_auc: float
    best_iteration: int
    feature_importance: dict[str, float]
    training_time_seconds: float
    mlflow_run_id: str | None = None


@dataclass(slots=True)
class XGBoostInferenceResult:
    """Result of XGBoost anomaly inference."""

    flow_key: str
    timestamp: float
    anomaly_probability: float
    is_anomaly: bool
    model_version: str
    inference_time_ms: float


# Feature names must match fast_path FlowFeatures.to_vector() order (51 features)
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

NUM_FEATURES = len(FEATURE_NAMES)

FEATURE_INDICES: dict[str, int] = {name: idx for idx, name in enumerate(FEATURE_NAMES)}


def get_feature_names() -> tuple[str, ...]:
    """Return ordered feature names."""
    return FEATURE_NAMES


def get_feature_indices() -> dict[str, int]:
    """Return mapping of feature name to index."""
    return FEATURE_INDICES.copy()


def select_features(vector: list[float], feature_names: list[str]) -> list[float]:
    """Select subset of features by name."""
    indices = [FEATURE_INDICES[name] for name in feature_names if name in FEATURE_INDICES]
    return [vector[i] for i in indices]


def flow_to_vector(flow: dict[str, Any]) -> list[float] | None:
    """Extract ordered feature vector from a flow dict."""
    features = flow.get("features")
    if not isinstance(features, dict):
        return None
    vector: list[float] = []
    for name in FEATURE_NAMES:
        value = features.get(name)
        if value is None:
            return None
        try:
            vector.append(float(value))
        except (TypeError, ValueError):
            return None
    return vector


def prepare_dataset(
    flows: list[dict[str, Any]],
    label_key: str = "label",
) -> tuple[list[list[float]], list[int]]:
    """Convert labeled flows to (X, y) for XGBoost.

    Expects each flow to have "features" dict and a label (0=normal, 1=anomaly).
    """
    x_data: list[list[float]] = []
    y: list[int] = []
    for flow in flows:
        vector = flow_to_vector(flow)
        if vector is None:
            continue
        label = flow.get(label_key)
        if label is None:
            continue
        try:
            label_int = int(label)
            if label_int not in (0, 1):
                continue
        except (TypeError, ValueError):
            continue
        x_data.append(vector)
        y.append(label_int)
    return x_data, y


def compute_scale_pos_weight(y: list[int]) -> float:
    """Compute scale_pos_weight for imbalanced binary classification."""
    pos = sum(y)
    neg = len(y) - pos
    return neg / pos if pos > 0 else 1.0


def get_model_params(
    config: XGBoostConfig, scale_pos_weight: float | None = None
) -> dict[str, Any]:
    """Build XGBoost parameter dict from config."""
    params: dict[str, Any] = {
        "n_estimators": config.n_estimators,
        "max_depth": config.max_depth,
        "learning_rate": config.learning_rate,
        "subsample": config.subsample,
        "colsample_bytree": config.colsample_bytree,
        "min_child_weight": config.min_child_weight,
        "reg_alpha": config.reg_alpha,
        "reg_lambda": config.reg_lambda,
        "objective": config.objective,
        "eval_metric": config.eval_metric,
        "tree_method": config.tree_method,
        "random_state": config.random_state,
        "n_jobs": config.n_jobs,
        "verbosity": 0,
    }
    if scale_pos_weight is not None:
        params["scale_pos_weight"] = scale_pos_weight
    return params
