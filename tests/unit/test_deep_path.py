"""Unit tests for deep path domain logic.

These only touch detection/deep_path/models.py, which is dependency-free by
design (no torch, no spark) so this suite runs on the bare test profile.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from detection.deep_path.models import (  # noqa: E402
    FEATURE_INDICES,
    FEATURE_NAMES,
    NUM_FEATURES,
    FlowSequence,
    compute_reconstruction_errors,
    create_sequences,
    get_feature_indices,
    normalize_anomaly_score,
    normalize_sequence,
    percentile_threshold,
    select_features,
    split_data,
)


class TestFastPathContract:
    """FEATURE_NAMES must track fast_path FlowFeatures.to_vector()."""

    def test_vector_length_matches_fast_path(self):
        from detection.fast_path.models import FlowFeatures  # noqa: E402

        assert len(FEATURE_NAMES) == len(FlowFeatures.feature_names())
        assert len(FlowFeatures.feature_names()) == NUM_FEATURES


def _vector(start: float = 0.0) -> list[float]:
    return [start + float(i) for i in range(NUM_FEATURES)]


def _flow(key: str, ts: float, start: float = 0.0) -> dict:
    return {"flow_key": key, "timestamp": ts, "features": _vector(start)}


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

    def test_select_subset(self):
        vector = _vector()
        picked = select_features(vector, ["duration", "fwd_bytes"])
        assert picked == [vector[0], vector[3]]


class TestNormalizeSequence:
    def test_zero_mean_unit_std_is_identity(self):
        seq = [_vector(), _vector(100.0)]
        means = [0.0] * NUM_FEATURES
        stds = [1.0] * NUM_FEATURES
        assert normalize_sequence(seq, means, stds) == seq

    def test_zero_std_avoids_division(self):
        seq = [[5.0] * NUM_FEATURES]
        means = [1.0] * NUM_FEATURES
        stds = [0.0] * NUM_FEATURES
        assert normalize_sequence(seq, means, stds) == [[0.0] * NUM_FEATURES]


class TestCreateSequences:
    def test_groups_by_flow_key(self):
        flows = [_flow("a", 1.0 + i) for i in range(5)]
        flows += [_flow("b", 1.0 + i) for i in range(5)]
        seqs = create_sequences(flows, 3)
        assert len(seqs) == 6  # (5-3+1) * 2 flows
        assert all(len(s.sequences) == 3 for s in seqs)

    def test_sorts_by_timestamp(self):
        flows = [_flow("a", 3.0), _flow("a", 1.0), _flow("a", 2.0)]
        seqs = create_sequences(flows, 3)
        assert len(seqs) == 1
        assert seqs[0].timestamps == [1.0, 2.0, 3.0]

    def test_short_flows_produce_nothing(self):
        flows = [_flow("a", 1.0), _flow("a", 2.0)]
        assert create_sequences(flows, 3) == []

    def test_skips_wrong_width_vectors(self):
        flows = [_flow("a", 1.0 + i) for i in range(4)]
        flows[0]["features"] = [1.0, 2.0]  # wrong width
        seqs = create_sequences(flows, 3)
        assert len(seqs) == 1

    def test_stride(self):
        flows = [_flow("a", 1.0 + i) for i in range(6)]
        assert len(create_sequences(flows, 3, stride=2)) == 2

    def test_ignores_flows_without_key(self):
        flows = [{"timestamp": 1.0, "features": _vector()}]
        assert create_sequences(flows, 2) == []


class TestSplitData:
    def _seqs(self, n: int) -> list[FlowSequence]:
        return [
            FlowSequence(
                flow_keys=[f"f{i % 3}"],
                sequences=[_vector(float(i))],
                timestamps=[float(i)],
            )
            for i in range(n)
        ]

    def test_ratios(self):
        train, val, test = split_data(self._seqs(100), 0.8, 0.1, 0.1)
        assert len(train) + len(val) + len(test) == 100

    def test_deterministic(self):
        first = split_data(self._seqs(50), 0.8, 0.1, 0.1)
        second = split_data(self._seqs(50), 0.8, 0.1, 0.1)
        assert [len(s) for s in first] == [len(s) for s in second]
        assert first[0][0].flow_keys == second[0][0].flow_keys

    def test_empty_input(self):
        assert split_data([], 0.8, 0.1, 0.1) == ([], [], [])

    def test_union_covers_all_flows(self):
        train, val, test = split_data(self._seqs(30), 0.8, 0.1, 0.1)
        all_keys = (
            {seq.flow_keys[0] for seq in train}
            | {seq.flow_keys[0] for seq in val}
            | {seq.flow_keys[0] for seq in test}
        )
        assert all_keys == {"f0", "f1", "f2"}

    def test_temporal_coverage(self):
        # Interleaved positions mean each split sees early AND late sequences,
        # unlike a contiguous slice which would isolate time ranges.
        train, val, test = split_data(self._seqs(30), 0.8, 0.1, 0.1)
        all_ts = (
            [s.timestamps[0] for s in train]
            + [s.timestamps[0] for s in val]
            + [s.timestamps[0] for s in test]
        )
        assert sorted(all_ts) == [float(i) for i in range(30)]


class TestReconstructionErrors:
    def test_identical_sequences_have_zero_error(self):
        seqs = [_vector(), _vector(5.0)]
        assert compute_reconstruction_errors(seqs, seqs) == [0.0, 0.0]

    def test_error_is_mse(self):
        orig = [[1.0, 2.0]]
        recon = [[3.0, 4.0]]
        assert compute_reconstruction_errors(orig, recon) == pytest.approx([4.0])


class TestPercentileThreshold:
    def test_empty(self):
        assert percentile_threshold([], 95.0) == 0.0

    def test_percentile_picks_expected_element(self):
        errors = [float(i) for i in range(100)]
        assert percentile_threshold(errors, 95.0) == 95.0
        assert percentile_threshold(errors, 50.0) == 50.0

    def test_clamps_to_last(self):
        assert percentile_threshold([1.0, 2.0], 100.0) == 2.0


class TestNormalizeAnomalyScore:
    def test_below_threshold_is_zero(self):
        assert normalize_anomaly_score(0.1, 0.5) == 0.0

    def test_above_threshold_without_max_is_one(self):
        assert normalize_anomaly_score(0.9, 0.5) == 1.0

    def test_interpolates_with_max(self):
        assert normalize_anomaly_score(0.75, 0.5, 1.0) == pytest.approx(0.5)

    def test_clamps_at_one(self):
        assert normalize_anomaly_score(10.0, 0.5, 1.0) == 1.0
