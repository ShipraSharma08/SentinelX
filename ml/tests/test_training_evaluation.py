import numpy as np
import pandas as pd
import pytest

from ml.training import train_baseline as training


def test_sample_csv_by_class_respects_limits_and_is_reproducible(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(training, "CHUNK_SIZE", 4)

    csv_path = tmp_path / "sample.csv"
    pd.DataFrame({
        "feature": list(range(12)),
        "Label": [
            "BENIGN", "ATTACK", "BENIGN", "DDoS",
            "BENIGN", "ATTACK", "BENIGN", "DDoS",
            "BENIGN", "ATTACK", "BENIGN", "DDoS",
        ],
    }).to_csv(csv_path, index=False)

    first = training.sample_csv_by_class(
        csv_path,
        per_class_limit=3,
        rng=np.random.default_rng(42),
    )
    second = training.sample_csv_by_class(
        csv_path,
        per_class_limit=3,
        rng=np.random.default_rng(42),
    )

    assert first["target"].value_counts().to_dict() == {0: 3, 1: 3}
    pd.testing.assert_frame_equal(first, second)


def test_sample_csv_by_class_returns_empty_for_empty_csv(tmp_path):
    csv_path = tmp_path / "empty.csv"
    pd.DataFrame({
        "feature": [1, 2],
        "Label": ["", None],
    }).to_csv(csv_path, index=False)

    result = training.sample_csv_by_class(
        csv_path,
        per_class_limit=3,
        rng=np.random.default_rng(42),
    )

    assert result.empty


def test_cap_training_classes_applies_limit_and_is_reproducible(
    monkeypatch,
):
    monkeypatch.setattr(training, "TOTAL_CLASS_LIMIT", 3)

    data = pd.DataFrame({
        "feature": range(10),
        "target": [0] * 6 + [1] * 4,
    })

    first = training.cap_training_classes(data)
    second = training.cap_training_classes(data)

    assert first["target"].value_counts().to_dict() == {0: 3, 1: 3}
    pd.testing.assert_frame_equal(first, second)


def test_cap_training_classes_rejects_missing_class():
    data = pd.DataFrame({
        "feature": [1, 2],
        "target": [0, 0],
    })

    with pytest.raises(ValueError, match="no samples for class 1"):
        training.cap_training_classes(data)


class DummyModel:
    def predict(self, features):
        assert list(features.columns) == ["feature"]
        return features["feature"].astype(int).to_numpy() % 2


def test_evaluate_full_capture_calculates_metrics_across_chunks(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(training, "CHUNK_SIZE", 2)

    csv_path = tmp_path / "holdout.csv"
    pd.DataFrame({
        "feature": [0, 1, 2, 3, 4],
        "Label": ["BENIGN", "BENIGN", "ATTACK", "ATTACK", ""],
        "test_only_feature": [10, 20, 30, 40, 50],
    }).to_csv(csv_path, index=False)

    result = training.evaluate_full_capture(
        model=DummyModel(),
        test_file=csv_path,
        feature_columns=pd.Index(["feature"]),
    )

    assert result["confusion_matrix"] == [[1, 1], [1, 1]]
    assert result["test_class_counts"] == {"0": 2, "1": 2}
    assert result["test_rows"] == 4
    assert result["ignored_unlabeled_rows"] == 1
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["true_negatives"] == 1
    assert result["true_positives"] == 1
    assert result["metrics"]["accuracy"] == pytest.approx(0.5)
    assert result["metrics"]["precision"] == pytest.approx(0.5)
    assert result["metrics"]["recall"] == pytest.approx(0.5)
    assert result["metrics"]["macro_f1"] == pytest.approx(0.5)


def test_evaluate_full_capture_rejects_missing_training_feature(tmp_path):
    csv_path = tmp_path / "holdout.csv"
    pd.DataFrame({
        "different_feature": [1, 2],
        "Label": ["BENIGN", "ATTACK"],
    }).to_csv(csv_path, index=False)

    with pytest.raises(ValueError, match="Training features missing"):
        training.evaluate_full_capture(
            model=DummyModel(),
            test_file=csv_path,
            feature_columns=pd.Index(["feature"]),
        )


def test_evaluate_full_capture_rejects_holdout_without_both_classes(
    tmp_path,
):
    csv_path = tmp_path / "holdout.csv"
    pd.DataFrame({
        "feature": [1, 2],
        "Label": ["BENIGN", "BENIGN"],
    }).to_csv(csv_path, index=False)

    with pytest.raises(ValueError, match="Expected both BENIGN and ATTACK"):
        training.evaluate_full_capture(
            model=DummyModel(),
            test_file=csv_path,
            feature_columns=pd.Index(["feature"]),
        )
