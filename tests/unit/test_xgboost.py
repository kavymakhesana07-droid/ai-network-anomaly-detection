"""Unit tests for XGBoost supervised detection domain logic.

Only touches detection/xgboost/models.py (dependency-free).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from detection.xgboost.models import (  # noqa: E402
    FEATURE_INDICES,
    FEATURE_NAMES,
    NUM_FEATURES,
    XGBoostConfig,
    compute_scale_pos_weight,
    flow_to_vector,
    get_feature_indices,
    get_feature_names,
    get_model_params,
    prepare_dataset,
    select_features,
)


def _flow(label: int, start: float = 0.0) -> dict:
    return {
        "flow_key": f"test_{start}",
        "timestamp": start,
        "features": {name: start + float(i) for i, name in enumerate(FEATURE_NAMES)},
        "label": label,
    }


class TestFeatureNames:
    def test_count_matches_index_map(self):
        assert len(FEATURE_NAMES) == NUM_FEATURES
        assert len(FEATURE_INDICES) == NUM_FEATURES

    def test_indices_are_zero_based_contiguous(self):
        assert sorted(FEATURE_INDICES.values()) == list(range(NUM_FEATURES))

    def test_get_feature_indices_returns_copy(self):
        first = get_feature_indices()
        first["duration"] = -1
        assert get_feature_indices()["duration"] == 0

    def test_get_feature_names_returns_tuple(self):
        names = get_feature_names()
        assert isinstance(names, tuple)
        assert len(names) == NUM_FEATURES

    def test_select_subset(self):
        vector = [float(i) for i in range(NUM_FEATURES)]
        picked = select_features(vector, ["duration", "fwd_bytes"])
        assert picked == [vector[0], vector[3]]


class TestConfig:
    def test_defaults(self):
        cfg = XGBoostConfig()
        assert cfg.n_estimators == 500
        assert cfg.max_depth == 8
        assert cfg.learning_rate == 0.05
        assert cfg.anomaly_threshold == 0.5


class TestFlowToVector:
    def test_valid_flow(self):
        flow = _flow(1)
        vec = flow_to_vector(flow)
        assert vec is not None
        assert len(vec) == NUM_FEATURES

    def test_missing_feature_returns_none(self):
        flow = _flow(1)
        del flow["features"]["duration"]
        assert flow_to_vector(flow) is None

    def test_non_numeric_feature_returns_none(self):
        flow = _flow(1)
        flow["features"]["duration"] = "not_a_number"
        assert flow_to_vector(flow) is None

    def test_missing_features_key_returns_none(self):
        flow = {"flow_key": "x", "timestamp": 1.0, "label": 1}
        assert flow_to_vector(flow) is None


class TestPrepareDataset:
    def test_filters_valid_labeled_flows(self):
        flows = [_flow(0), _flow(1), _flow(0), _flow(1)]
        x_data, y = prepare_dataset(flows)
        assert len(x_data) == 4
        assert y == [0, 1, 0, 1]

    def test_skips_missing_label(self):
        flows = [
            _flow(0),
            {"flow_key": "x", "timestamp": 1.0, "features": dict.fromkeys(FEATURE_NAMES, 0.0)},
        ]
        x_data, y = prepare_dataset(flows)
        assert len(x_data) == 1

    def test_skips_invalid_label(self):
        flows = [_flow(0), _flow(1)]
        flows[1]["label"] = 2
        x_data, y = prepare_dataset(flows)
        assert len(x_data) == 1


class TestScalePosWeight:
    def test_balanced(self):
        assert compute_scale_pos_weight([0, 1, 0, 1]) == 1.0

    def test_imbalanced(self):
        # 10 normal, 2 anomaly -> 10/2 = 5
        assert compute_scale_pos_weight([0] * 10 + [1] * 2) == 5.0

    def test_no_positive(self):
        assert compute_scale_pos_weight([0, 0, 0]) == 1.0


class TestModelParams:
    def test_includes_scale_pos_weight(self):
        cfg = XGBoostConfig()
        params = get_model_params(cfg, scale_pos_weight=7.5)
        assert params["scale_pos_weight"] == 7.5
        assert params["objective"] == "binary:logistic"
        assert params["eval_metric"] == "auc"

    def test_without_scale_pos_weight(self):
        cfg = XGBoostConfig()
        params = get_model_params(cfg, scale_pos_weight=None)
        assert "scale_pos_weight" not in params


class TestFastPathContract:
    """FEATURE_NAMES must track fast_path FlowFeatures.to_vector()."""

    def test_vector_length_matches_fast_path(self):
        from detection.fast_path.models import FlowFeatures  # noqa: E402

        assert len(FEATURE_NAMES) == len(FlowFeatures.feature_names())
        assert len(FlowFeatures.feature_names()) == NUM_FEATURES
