"""Unit tests for Model Registry domain logic.

Only touches detection/model_registry/models.py (dependency-free).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from detection.model_registry.models import (  # noqa: E402
    DetectorType,
    ModelMetadata,
    ModelStage,
    create_model_name,
    format_model_uri,
    is_production_ready,
    model_version_sort_key,
    parse_model_name,
    validate_stage_transition,
)


class TestModelStages:
    def test_stage_enum_values(self):
        assert ModelStage.NONE.value == "None"
        assert ModelStage.STAGING.value == "Staging"
        assert ModelStage.PRODUCTION.value == "Production"
        assert ModelStage.ARCHIVED.value == "Archived"


class TestDetectorType:
    def test_all_detectors(self):
        assert DetectorType.FAST_PATH.value == "fast_path"
        assert DetectorType.DEEP_PATH.value == "deep_path"
        assert DetectorType.XGBOOST.value == "xgboost"


class TestModelNameGeneration:
    def test_create_model_name(self):
        assert create_model_name(DetectorType.FAST_PATH) == "fast_path"
        assert create_model_name(DetectorType.DEEP_PATH) == "deep_path"
        assert create_model_name(DetectorType.XGBOOST) == "xgboost"

    def test_create_model_name_with_suffix(self):
        assert create_model_name(DetectorType.FAST_PATH, "v2") == "fast_path-v2"
        assert create_model_name(DetectorType.XGBOOST, "exp1") == "xgboost-exp1"

    def test_parse_model_name(self):
        dt, suffix = parse_model_name("fast_path")
        assert dt == DetectorType.FAST_PATH
        assert suffix is None

        dt, suffix = parse_model_name("deep_path-v2")
        assert dt == DetectorType.DEEP_PATH
        assert suffix == "v2"

        dt, suffix = parse_model_name("xgboost-exp1")
        assert dt == DetectorType.XGBOOST
        assert suffix == "exp1"

    def test_parse_unknown_name(self):
        dt, suffix = parse_model_name("unknown-model")
        assert dt is None
        assert suffix is None


class TestStageTransitions:
    def test_none_to_staging_allowed(self):
        allowed, _ = validate_stage_transition(ModelStage.NONE, ModelStage.STAGING)
        assert allowed

    def test_staging_to_production_allowed(self):
        allowed, _ = validate_stage_transition(ModelStage.STAGING, ModelStage.PRODUCTION)
        assert allowed

    def test_staging_to_archived_allowed(self):
        allowed, _ = validate_stage_transition(ModelStage.STAGING, ModelStage.ARCHIVED)
        assert allowed

    def test_production_to_archived_allowed(self):
        allowed, _ = validate_stage_transition(ModelStage.PRODUCTION, ModelStage.ARCHIVED)
        assert allowed

    def test_archive_always_allowed(self):
        for stage in ModelStage:
            allowed, _ = validate_stage_transition(stage, ModelStage.ARCHIVED)
            assert allowed, f"Archive should be allowed from {stage.value}"

    def test_none_to_production_blocked(self):
        allowed, msg = validate_stage_transition(ModelStage.NONE, ModelStage.PRODUCTION)
        assert not allowed
        assert "not allowed" in msg

    def test_production_to_staging_blocked(self):
        allowed, msg = validate_stage_transition(ModelStage.PRODUCTION, ModelStage.STAGING)
        assert not allowed

    def test_archived_transitions_blocked(self):
        allowed, _ = validate_stage_transition(ModelStage.ARCHIVED, ModelStage.STAGING)
        assert not allowed
        allowed, _ = validate_stage_transition(ModelStage.ARCHIVED, ModelStage.PRODUCTION)
        assert not allowed
        allowed, _ = validate_stage_transition(ModelStage.ARCHIVED, ModelStage.NONE)
        assert not allowed


class TestModelUri:
    def test_format_version(self):
        assert format_model_uri("fast_path", "1") == "models:/fast_path/1"
        assert format_model_uri("deep_path", "2.3") == "models:/deep_path/2.3"

    def test_format_stage(self):
        assert format_model_uri("fast_path", ModelStage.STAGING) == "models:/fast_path/Staging"
        assert format_model_uri("xgboost", ModelStage.PRODUCTION) == "models:/xgboost/Production"


class TestVersionSorting:
    def test_integer_versions(self):
        versions = ["1", "2", "10", "5"]
        sorted_v = sorted(versions, key=model_version_sort_key)
        assert sorted_v == ["1", "2", "5", "10"]

    def test_semver(self):
        versions = ["1.0.0", "1.0.1", "1.1.0", "2.0.0"]
        sorted_v = sorted(versions, key=model_version_sort_key)
        assert sorted_v == ["1.0.0", "1.0.1", "1.1.0", "2.0.0"]

    def test_mixed_versions(self):
        versions = ["1", "2.0", "1.5", "10"]
        sorted_v = sorted(versions, key=model_version_sort_key)
        # Non-numeric fallback sorts after numeric
        assert sorted_v == ["1", "1.5", "2.0", "10"]


class TestProductionReadiness:
    def _base_metadata(self, **overrides) -> ModelMetadata:
        defaults = {
            "name": "fast_path",
            "version": "1",
            "detector_type": DetectorType.FAST_PATH,
            "stage": ModelStage.STAGING,
            "metrics": {"test_auc": 0.95},
            "onnx_path": "model.onnx",
            "threshold_path": "threshold.json",
        }
        defaults.update(overrides)
        return ModelMetadata(**defaults)

    def test_ready_model_passes(self):
        meta = self._base_metadata()
        ready, reasons = is_production_ready(meta)
        assert ready
        assert not reasons

    def test_wrong_stage_fails(self):
        meta = self._base_metadata(stage=ModelStage.NONE)
        ready, reasons = is_production_ready(meta)
        assert not ready
        assert any("Staging stage first" in r for r in reasons)

    def test_low_auc_fails(self):
        meta = self._base_metadata(metrics={"test_auc": 0.80})
        ready, reasons = is_production_ready(meta)
        assert not ready
        assert any("AUC" in r for r in reasons)

    def test_missing_onnx_fails_for_fast_path(self):
        meta = self._base_metadata(onnx_path=None)
        ready, reasons = is_production_ready(meta)
        assert not ready
        assert any("ONNX" in r for r in reasons)

    def test_missing_threshold_fails(self):
        meta = self._base_metadata(threshold_path=None)
        ready, reasons = is_production_ready(meta)
        assert not ready
        assert any("Threshold" in r for r in reasons)

    def test_missing_normalization_ok_for_fast_path(self):
        meta = self._base_metadata(normalization_path=None)
        ready, reasons = is_production_ready(meta)
        # Fast path doesn't require normalization artifact
        assert ready

    def test_missing_normalization_fails_for_deep_path(self):
        meta = self._base_metadata(
            detector_type=DetectorType.DEEP_PATH,
            normalization_path=None,
        )
        ready, reasons = is_production_ready(meta)
        assert not ready
        assert any("Normalization" in r for r in reasons)
