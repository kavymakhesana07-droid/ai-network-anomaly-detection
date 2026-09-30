"""Offline training for the XGBoost supervised detector.

Entry point: python -m detection.xgboost.main train --input labeled.json --output DIR

Heavy ML imports (xgboost, pandas, mlflow, sklearn) are loaded lazily so
importing this module stays cheap and unit tests never touch the ML stack.
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
    XGBoostConfig,
    XGBoostTrainingResult,
    compute_scale_pos_weight,
    get_model_params,
    prepare_dataset,
)

logger = structlog.get_logger(__name__)


def train_model(
    input_path: Path,
    output_dir: Path,
    _model_path: str,  # kept for API compatibility
    model_name: str,
    n_estimators: int,
    threshold: float,
    mlflow_tracking_uri: str | None = None,
    mlflow_experiment_name: str = "xgboost-supervised",
) -> XGBoostTrainingResult:
    """Train XGBoost binary classifier on labeled flows."""
    import xgboost as xgb  # lazy - heavy, runtime only
    from sklearn.model_selection import train_test_split  # lazy - heavy, runtime only

    started = time.monotonic()

    # Load and prepare data
    data = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        msg = f"{input_path} must contain a JSON list of flows"
        raise TypeError(msg)
    logger.info("Loaded flows", count=len(data))

    x_data, y = prepare_dataset(cast(list[dict[str, Any]], data))
    if len(x_data) < 100:
        msg = f"too few valid samples: {len(x_data)}"
        raise ValueError(msg)
    pos = sum(y)
    neg = len(y) - pos
    logger.info(
        "Prepared dataset", total=len(x_data), normal=neg, anomaly=pos, ratio=neg / max(1, pos)
    )

    x_train, x_temp, y_train, y_temp = train_test_split(
        x_data, y, test_size=0.3, random_state=42, stratify=y
    )
    x_val, x_test, y_val, y_test = train_test_split(
        x_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    logger.info("Split", train=len(x_train), val=len(x_val), test=len(x_test))

    # Build DMatrix
    dtrain = xgb.DMatrix(x_train, label=y_train, feature_names=list(FEATURE_NAMES))
    dval = xgb.DMatrix(x_val, label=y_val, feature_names=list(FEATURE_NAMES))
    dtest = xgb.DMatrix(x_test, label=y_test, feature_names=list(FEATURE_NAMES))

    # Config
    config = XGBoostConfig()
    config.n_estimators = n_estimators
    scale_pos_weight = compute_scale_pos_weight(y_train)
    params = get_model_params(config, scale_pos_weight)

    # Train with early stopping
    evals = [(dtrain, "train"), (dval, "val")]
    evals_result: dict[str, Any] = {}
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=config.n_estimators,
        evals=evals,
        early_stopping_rounds=config.early_stopping_rounds,
        evals_result=evals_result,
        verbose_eval=False,
    )
    best_iteration = (
        model.best_iteration + 1 if model.best_iteration is not None else config.n_estimators
    )
    logger.info("Training complete", best_iteration=best_iteration)

    # Evaluate
    from sklearn.metrics import roc_auc_score  # lazy - heavy, runtime only

    train_pred = model.predict(xgb.DMatrix(x_train, feature_names=list(FEATURE_NAMES)))
    val_pred = model.predict(dval)
    test_pred = model.predict(dtest)

    train_auc = float(roc_auc_score(y_train, train_pred))
    val_auc = float(roc_auc_score(y_val, val_pred))
    test_auc = float(roc_auc_score(y_test, test_pred))
    logger.info("AUC scores", train=train_auc, val=val_auc, test=test_auc)

    # Feature importance
    importance = model.get_score(importance_type="gain")
    importance = {k: float(v) for k, v in importance.items()}
    # Normalize to sum=1
    total = sum(importance.values())
    if total > 0:
        importance = {k: v / total for k, v in importance.items()}

    # Calibrate threshold on validation set (you can tune this)
    # For now use the provided threshold
    calibrated_threshold = threshold

    version = time.strftime("%Y%m%d-%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save model (native JSON format)
    model_file = output_dir / model_name
    model.save_model(str(model_file))
    logger.info("Saved XGBoost model", path=str(model_file))

    # Save artifacts
    (output_dir / "threshold.json").write_text(
        json.dumps({"threshold": calibrated_threshold, "source": "configured"}, indent=2)
    )
    (output_dir / "model_version.json").write_text(
        json.dumps(
            {
                "version": version,
                "features": NUM_FEATURES,
                "n_estimators": best_iteration,
                "algorithm": "xgboost_binary",
            },
            indent=2,
        )
    )

    # MLflow logging (best-effort)
    mlflow_run_id: str | None = None
    if mlflow_tracking_uri:
        try:
            import mlflow  # lazy - heavy, runtime only

            mlflow.set_tracking_uri(mlflow_tracking_uri)
            mlflow.set_experiment(mlflow_experiment_name)
            with mlflow.start_run() as run:
                mlflow.log_params({
                    **{k: v for k, v in params.items() if k != "verbosity"},
                    "scale_pos_weight": scale_pos_weight,
                    "best_iteration": best_iteration,
                })
                mlflow.log_metrics({
                    "train_auc": train_auc,
                    "val_auc": val_auc,
                    "test_auc": test_auc,
                    "threshold": calibrated_threshold,
                    "samples": len(x_data),
                    "positive_ratio": pos / len(y),
                })
                mlflow.log_artifacts(str(output_dir))
                mlflow_run_id = cast(str, run.info.run_id)
                logger.info("Logged MLflow run", run_id=mlflow_run_id)
        except Exception as exc:
            logger.warning("MLflow logging skipped", error=str(exc))

    elapsed = time.monotonic() - started
    result = XGBoostTrainingResult(
        model_version=version,
        train_auc=train_auc,
        val_auc=val_auc,
        test_auc=test_auc,
        best_iteration=best_iteration,
        feature_importance=importance,
        training_time_seconds=elapsed,
        mlflow_run_id=mlflow_run_id,
    )
    logger.info(
        "Training complete",
        version=version,
        test_auc=test_auc,
        threshold=calibrated_threshold,
    )
    return result
