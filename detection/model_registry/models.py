"""
Model Registry Domain Logic - MLflow-backed model versioning and promotion.

No external ML dependencies (mlflow) so unit tests run fast.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class ModelStage(StrEnum):
    """MLflow model stages."""

    NONE = "None"
    STAGING = "Staging"
    PRODUCTION = "Production"
    ARCHIVED = "Archived"


class DetectorType(StrEnum):
    """Supported detector types in the registry."""

    FAST_PATH = "fast_path"
    DEEP_PATH = "deep_path"
    XGBOOST = "xgboost"


@dataclass(slots=True)
class ModelMetadata:
    """Immutable model metadata."""

    name: str
    version: str
    detector_type: DetectorType
    stage: ModelStage = ModelStage.NONE
    run_id: str = ""
    experiment_id: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)

    # Artifact paths (relative to MLflow artifact URI)
    artifact_path: str = ""
    onnx_path: str | None = None
    threshold_path: str | None = None
    normalization_path: str | None = None
    feature_names_path: str | None = None


@dataclass(slots=True)
class ModelRegistryConfig:
    """Configuration for the Model Registry service."""

    mlflow_tracking_uri: str = "http://mlflow:5000"
    mlflow_registry_uri: str = "http://mlflow:5000"
    default_artifact_root: str = "s3://mlflow-artifacts"

    # Promotion policies
    auto_promote_staging: bool = True
    min_staging_days: int = 1
    require_approval_production: bool = True

    # Retention
    max_versions_per_stage: int = 10
    archive_after_days: int = 90

    # Health checks
    health_check_interval_seconds: int = 30


@dataclass(slots=True)
class PromotionRequest:
    """Request to promote a model version to a new stage."""

    model_name: str
    version: str
    target_stage: ModelStage
    requested_by: str
    reason: str = ""
    approved_by: str | None = None
    approved_at: datetime | None = None


@dataclass(slots=True)
class ModelSearchResult:
    """Result of a model search/query."""

    models: list[ModelMetadata]
    total_count: int
    page: int
    page_size: int


@dataclass(slots=True)
class HealthCheckResult:
    """Health check result for the registry."""

    healthy: bool
    mlflow_reachable: bool
    artifact_store_reachable: bool
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: str | None = None


def create_model_name(detector_type: DetectorType, suffix: str = "") -> str:
    """Generate a standardized model name."""
    base = detector_type.value
    if suffix:
        return f"{base}-{suffix}"
    return base


def parse_model_name(name: str) -> tuple[DetectorType | None, str | None]:
    """Parse detector type and suffix from model name."""
    for dt in DetectorType:
        if name.startswith(dt.value):
            suffix = name[len(dt.value) :]
            if suffix.startswith("-"):
                suffix = suffix[1:]
            return dt, suffix or None
    return None, None


def validate_stage_transition(current: ModelStage, target: ModelStage) -> tuple[bool, str]:
    """Validate if a stage transition is allowed.

    Allowed transitions:
    - None -> Staging
    - Staging -> Production, Archived
    - Production -> Archived
    - Any -> Archived (archive is always allowed)
    """
    if target == ModelStage.ARCHIVED:
        return True, "Archiving is always allowed"

    allowed = {
        ModelStage.NONE: {ModelStage.STAGING},
        ModelStage.STAGING: {ModelStage.PRODUCTION, ModelStage.ARCHIVED},
        ModelStage.PRODUCTION: {ModelStage.ARCHIVED},
        ModelStage.ARCHIVED: set(),
    }

    if target in allowed.get(current, set()):
        return True, f"Transition from {current.value} to {target.value} allowed"

    return (
        False,
        f"Transition from {current.value} to {target.value} not allowed. Allowed: {[s.value for s in allowed.get(current, set())]}",
    )


def get_detector_model_names() -> list[str]:
    """Get all registered detector model names."""
    return [f"{dt.value}" for dt in DetectorType]


def format_model_uri(model_name: str, version: str | ModelStage) -> str:
    """Format an MLflow model URI for a given version or stage."""
    if isinstance(version, ModelStage):
        return f"models:/{model_name}/{version.value}"
    return f"models:/{model_name}/{version}"


def extract_model_info_from_uri(uri: str) -> tuple[str, str] | None:
    """Extract model name and version from an MLflow model URI.

    Supports: models:/<name>/<version>, models:/<name>/<stage>, models:/<name>@<alias>
    """
    if not uri.startswith("models:/"):
        return None
    parts = uri[8:].split("/", 1)
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


def model_version_sort_key(version: str) -> tuple[int, ...]:
    """Parse version string for sorting (handles semver and integer versions)."""
    parts = version.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        # Fallback: lexicographic for non-numeric versions
        return (0, *version)


def is_production_ready(metadata: ModelMetadata) -> tuple[bool, list[str]]:
    """Check if a model meets production readiness criteria.

    Returns (ready, reasons_if_not).
    """
    reasons: list[str] = []

    if metadata.stage != ModelStage.STAGING:
        reasons.append("Model must be in Staging stage first")

    if not metadata.metrics:
        reasons.append("No evaluation metrics recorded")

    # Check minimum metrics thresholds (configurable in real impl)
    if "test_auc" in metadata.metrics and metadata.metrics["test_auc"] < 0.85:
        reasons.append(f"Test AUC {metadata.metrics['test_auc']:.3f} below threshold 0.85")

    if not metadata.onnx_path and metadata.detector_type in (
        DetectorType.FAST_PATH,
        DetectorType.XGBOOST,
    ):
        reasons.append("ONNX artifact missing for fast-path detector")

    if not metadata.threshold_path:
        reasons.append("Threshold artifact missing")

    if not metadata.normalization_path and metadata.detector_type != DetectorType.FAST_PATH:
        reasons.append("Normalization artifact missing")

    return len(reasons) == 0, reasons
