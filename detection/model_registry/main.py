"""
Model Registry Service - MLflow-backed model versioning, promotion, and serving.

Provides REST API for:
- Model CRUD (register, get, search, delete)
- Stage promotion (None -> Staging -> Production -> Archived)
- Health checks and monitoring
- Webhook notifications for CI/CD integration
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    DetectorType,
    HealthCheckResult,
    ModelMetadata,
    ModelSearchResult,
    ModelStage,
    create_model_name,
    format_model_uri,
    is_production_ready,
    validate_stage_transition,
)

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # MLflow
    mlflow_tracking_uri: str = Field(default="http://mlflow:5000", alias="MLFLOW_TRACKING_URI")
    mlflow_registry_uri: str = Field(default="http://mlflow:5000", alias="MLFLOW_REGISTRY_URI")
    mlflow_artifact_root: str = Field(default="s3://mlflow-artifacts", alias="MLFLOW_ARTIFACT_ROOT")

    # Service
    host: str = Field(default="0.0.0.0", alias="HOST")  # noqa: S104 - required for container networking
    port: int = Field(default=8080, alias="PORT")
    log_level: str = Field(default="info", alias="LOG_LEVEL")

    # Registry policies
    auto_promote_staging: bool = Field(default=True, alias="AUTO_PROMOTE_STAGING")
    min_staging_days: int = Field(default=1, alias="MIN_STAGING_DAYS")
    require_approval_production: bool = Field(default=True, alias="REQUIRE_APPROVAL_PRODUCTION")

    # Limits
    max_versions_per_stage: int = Field(default=10, alias="MAX_VERSIONS_PER_STAGE")
    archive_after_days: int = Field(default=90, alias="ARCHIVE_AFTER_DAYS")


class ModelRegisterRequest(BaseModel):
    detector_type: DetectorType
    run_id: str
    experiment_id: str
    description: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    artifact_path: str = ""
    onnx_path: str | None = None
    threshold_path: str | None = None
    normalization_path: str | None = None
    feature_names_path: str | None = None

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, v: str) -> str:
        if not v:
            raise ValueError("run_id is required")  # noqa: TRY003
        return v


class ModelPromoteRequest(BaseModel):
    version: str
    target_stage: ModelStage
    reason: str = ""

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if not v:
            raise ValueError("version is required")  # noqa: TRY003
        return v


class ModelPromoteResponse(BaseModel):
    success: bool
    model_name: str
    version: str
    previous_stage: ModelStage
    new_stage: ModelStage
    message: str


class ModelSearchParams(BaseModel):
    detector_type: DetectorType | None = None
    stage: ModelStage | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class ModelRegistryService:
    """Model Registry Service backed by MLflow."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.mlflow_client: Any = None
        self._healthy = False

    async def initialize(self) -> None:
        """Initialize MLflow client and verify connectivity."""
        import mlflow
        from mlflow.tracking import MlflowClient

        mlflow.set_tracking_uri(self.settings.mlflow_tracking_uri)
        mlflow.set_registry_uri(self.settings.mlflow_registry_uri)
        self.mlflow_client = MlflowClient()

        # Verify connectivity
        try:
            self.mlflow_client.search_experiments(max_results=1)
            self._healthy = True
            logger.info("MLflow client initialized", uri=self.settings.mlflow_tracking_uri)
        except Exception as exc:
            self._healthy = False
            logger.exception("MLflow initialization failed", error=str(exc))
            raise

    async def health_check(self) -> HealthCheckResult:
        """Perform health check."""
        mlflow_ok = False
        artifact_ok = False
        error = None

        try:
            self.mlflow_client.search_experiments(max_results=1)
            mlflow_ok = True
        except Exception as exc:
            error = str(exc)

        # Check artifact store (simplified)
        try:
            import mlflow

            mlflow.get_artifact_uri()
            artifact_ok = True
        except Exception as exc:
            logger.debug("Artifact store check failed", error=str(exc))

        return HealthCheckResult(
            healthy=mlflow_ok and artifact_ok,
            mlflow_reachable=mlflow_ok,
            artifact_store_reachable=artifact_ok,
            error=error,
        )

    def _metadata_to_dict(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Convert ModelMetadata to dict for JSON serialization."""
        data = asdict(metadata)
        data["detector_type"] = metadata.detector_type.value
        data["stage"] = metadata.stage.value
        data["created_at"] = metadata.created_at.isoformat()
        data["updated_at"] = metadata.updated_at.isoformat()
        return data

    async def register_model(self, request: ModelRegisterRequest) -> ModelMetadata:
        """Register a new model version from an MLflow run."""
        model_name = create_model_name(request.detector_type)

        import mlflow

        # Get the run to verify it exists
        run = self.mlflow_client.get_run(request.run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Run {request.run_id} not found")

        # Register model in MLflow
        model_uri = f"runs:/{request.run_id}/{request.artifact_path or 'model'}"
        registered = mlflow.register_model(model_uri, model_name)

        # Update metadata
        client = self.mlflow_client
        client.update_model_version(
            name=model_name,
            version=registered.version,
            description=request.description,
        )

        # Set tags
        for k, v in request.tags.items():
            client.set_model_version_tag(model_name, registered.version, k, v)

        # Create our metadata object
        metadata = ModelMetadata(
            name=model_name,
            version=registered.version,
            detector_type=request.detector_type,
            stage=ModelStage.NONE,
            run_id=request.run_id,
            experiment_id=request.experiment_id,
            description=request.description,
            tags=request.tags,
            metrics=request.metrics,
            params=request.params,
            artifact_path=request.artifact_path,
            onnx_path=request.onnx_path,
            threshold_path=request.threshold_path,
            normalization_path=request.normalization_path,
            feature_names_path=request.feature_names_path,
        )

        logger.info("Model registered", name=model_name, version=registered.version)
        return metadata

    async def get_model(self, model_name: str, version: str | ModelStage) -> ModelMetadata:
        """Get model metadata by name and version/stage."""
        client = self.mlflow_client

        try:
            if isinstance(version, ModelStage):
                mv = client.get_model_version(model_name, version.value)
            else:
                mv = client.get_model_version(model_name, version)
        except Exception as exc:
            raise HTTPException(
                status_code=404, detail=f"Model {model_name} version {version} not found"
            ) from exc

        # Build metadata from MLflow
        metadata = ModelMetadata(
            name=model_name,
            version=mv.version,
            detector_type=DetectorType(mv.tags.get("detector_type", "unknown")),
            stage=ModelStage(mv.current_stage),
            run_id=mv.run_id,
            description=mv.description or "",
            tags={k: v for k, v in mv.tags.items() if k not in ("detector_type",)},
            created_at=datetime.fromtimestamp(mv.creation_timestamp / 1000),
            updated_at=datetime.fromtimestamp(mv.last_updated_timestamp / 1000),
        )
        return metadata

    async def search_models(self, params: ModelSearchParams) -> ModelSearchResult:
        """Search models with filters and pagination."""
        client = self.mlflow_client

        filter_string = ""
        conditions = []
        if params.detector_type:
            conditions.append(f"tags.detector_type = '{params.detector_type.value}'")
        if params.stage and params.stage != ModelStage.NONE:
            conditions.append(f"current_stage = '{params.stage.value}'")
        filter_string = " and ".join(conditions) if conditions else ""

        all_versions = client.search_model_versions(filter_string)
        total = len(all_versions)

        # Apply pagination
        start = (params.page - 1) * params.page_size
        end = start + params.page_size
        page_versions = all_versions[start:end]

        models = []
        for mv in page_versions:
            detector_type_str = mv.tags.get("detector_type", "unknown")
            try:
                detector_type = DetectorType(detector_type_str)
            except ValueError:
                detector_type = DetectorType.FAST_PATH

            metadata = ModelMetadata(
                name=mv.name,
                version=mv.version,
                detector_type=detector_type,
                stage=ModelStage(mv.current_stage),
                run_id=mv.run_id,
                description=mv.description or "",
                tags={k: v for k, v in mv.tags.items() if k != "detector_type"},
                created_at=datetime.fromtimestamp(mv.creation_timestamp / 1000),
                updated_at=datetime.fromtimestamp(mv.last_updated_timestamp / 1000),
            )
            models.append(metadata)

        return ModelSearchResult(
            models=models,
            total_count=total,
            page=params.page,
            page_size=params.page_size,
        )

    async def promote_model(
        self, model_name: str, request: ModelPromoteRequest, requested_by: str
    ) -> ModelPromoteResponse:
        """Promote a model version to a new stage."""
        client = self.mlflow_client

        # Get current stage
        current_mv = client.get_model_version(model_name, request.version)
        current_stage = ModelStage(current_mv.current_stage)

        # Validate transition
        allowed, msg = validate_stage_transition(current_stage, request.target_stage)
        if not allowed:
            raise HTTPException(status_code=400, detail=msg)

        # Check production readiness if promoting to Production
        if request.target_stage == ModelStage.PRODUCTION:
            metadata = await self.get_model(model_name, request.version)
            ready, reasons = is_production_ready(metadata)
            if not ready:
                raise HTTPException(
                    status_code=400,
                    detail=f"Model not production ready: {'; '.join(reasons)}",
                )

        # Perform transition
        client.transition_model_version_stage(
            name=model_name,
            version=request.version,
            stage=request.target_stage.value,
            archive_existing_versions=request.target_stage == ModelStage.PRODUCTION,
        )

        logger.info(
            "Model promoted",
            model=model_name,
            version=request.version,
            from_stage=current_stage.value,
            to_stage=request.target_stage.value,
            requested_by=requested_by,
        )

        return ModelPromoteResponse(
            success=True,
            model_name=model_name,
            version=request.version,
            previous_stage=current_stage,
            new_stage=request.target_stage,
            message=f"Promoted from {current_stage.value} to {request.target_stage.value}",
        )

    async def archive_model(self, model_name: str, version: str) -> dict[str, Any]:
        """Archive a model version."""
        client = self.mlflow_client
        client.transition_model_version_stage(
            name=model_name,
            version=version,
            stage=ModelStage.ARCHIVED.value,
        )
        return {"success": True, "model_name": model_name, "version": version, "stage": "Archived"}

    async def delete_model_version(self, model_name: str, version: str) -> dict[str, Any]:
        """Delete a specific model version."""
        client = self.mlflow_client
        client.delete_model_version(name=model_name, version=version)
        return {"success": True, "model_name": model_name, "version": version}

    async def get_model_uri(self, model_name: str, version: str | ModelStage) -> str:
        """Get the model URI for serving."""
        return format_model_uri(model_name, version)


# FastAPI app
settings = Settings()

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)

registry = ModelRegistryService(settings)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await registry.initialize()
    yield


app = FastAPI(
    title="Model Registry Service",
    description="MLflow-backed model registry for anomaly detection models",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    result = await registry.health_check()
    return asdict(result)


@app.get("/models")
async def search_models(
    detector_type: DetectorType | None = None,
    stage: ModelStage | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    params = ModelSearchParams(
        detector_type=detector_type,
        stage=stage,
        page=page,
        page_size=page_size,
    )
    result = await registry.search_models(params)
    return {
        "models": [asdict(m) for m in result.models],
        "total_count": result.total_count,
        "page": result.page,
        "page_size": result.page_size,
    }


@app.get("/models/{model_name}/versions/{version}")
async def get_model(model_name: str, version: str) -> dict[str, Any]:
    # Handle stage names
    try:
        stage = ModelStage(version)
        metadata = await registry.get_model(model_name, stage)
    except ValueError:
        metadata = await registry.get_model(model_name, version)
    return asdict(metadata)


@app.post("/models")
async def register_model(request: ModelRegisterRequest) -> dict[str, Any]:
    metadata = await registry.register_model(request)
    return asdict(metadata)


@app.post("/models/{model_name}/versions/{version}/promote")
async def promote_model(
    model_name: str, version: str, request: ModelPromoteRequest
) -> ModelPromoteResponse:
    # In real impl, get user from auth context
    request.version = version  # ensure version matches path
    response = await registry.promote_model(model_name, request, requested_by="api")
    return response


@app.post("/models/{model_name}/versions/{version}/archive")
async def archive_model(model_name: str, version: str) -> dict[str, Any]:
    return await registry.archive_model(model_name, version)


@app.delete("/models/{model_name}/versions/{version}")
async def delete_model_version(model_name: str, version: str) -> dict[str, Any]:
    return await registry.delete_model_version(model_name, version)


@app.get("/models/{model_name}/versions/{version}/uri")
async def get_model_uri(model_name: str, version: str) -> dict[str, str]:
    try:
        stage = ModelStage(version)
        uri = await registry.get_model_uri(model_name, stage)
    except ValueError:
        uri = await registry.get_model_uri(model_name, version)
    return {"uri": uri}


@app.get("/models/{model_name}/production-ready/{version}")
async def check_production_ready(model_name: str, version: str) -> dict[str, Any]:
    metadata = await registry.get_model(model_name, version)
    ready, reasons = is_production_ready(metadata)
    return {"ready": ready, "reasons": reasons}


def main() -> None:
    uvicorn.run(
        "detection.model_registry.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=False,
    )


if __name__ == "__main__":
    main()
