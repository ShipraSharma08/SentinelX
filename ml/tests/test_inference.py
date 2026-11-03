import math

import pytest

from ml.inference.predict import _load_model, predict_flow


@pytest.fixture
def valid_features():
    """Create a fresh feature dictionary for each test."""
    _, feature_names = _load_model()
    return {feature: 0.0 for feature in feature_names}


def test_prediction_returns_expected_structure(valid_features):
    result = predict_flow(valid_features)

    assert set(result) == {
        "prediction",
        "attack_probability",
        "model",
    }


def test_prediction_has_valid_class(valid_features):
    result = predict_flow(valid_features)

    assert result["prediction"] in {"BENIGN", "ATTACK"}


def test_attack_probability_is_valid(valid_features):
    result = predict_flow(valid_features)

    assert math.isfinite(result["attack_probability"])
    assert 0.0 <= result["attack_probability"] <= 1.0


def test_model_name_is_correct(valid_features):
    result = predict_flow(valid_features)

    assert result["model"] == "web_coverage_candidate"


def test_missing_feature_is_rejected(valid_features):
    invalid_features = valid_features.copy()
    invalid_features.pop(next(iter(invalid_features)))

    with pytest.raises(ValueError, match="Feature mismatch"):
        predict_flow(invalid_features)


def test_unexpected_feature_is_rejected(valid_features):
    invalid_features = valid_features.copy()
    invalid_features["unexpected_feature"] = 1.0

    with pytest.raises(ValueError, match="Feature mismatch"):
        predict_flow(invalid_features)


def test_duplicate_normalized_feature_name_is_rejected(valid_features):
    invalid_features = valid_features.copy()
    feature_name = next(iter(invalid_features))
    invalid_features[f" {feature_name} "] = 1.0

    with pytest.raises(ValueError, match="Duplicate feature names"):
        predict_flow(invalid_features)


@pytest.mark.parametrize(
    "invalid_value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_non_finite_feature_value_is_rejected(
    valid_features,
    invalid_value,
):
    invalid_features = valid_features.copy()
    invalid_features[next(iter(invalid_features))] = invalid_value

    with pytest.raises(ValueError, match="finite"):
        predict_flow(invalid_features)


def test_non_dictionary_input_is_rejected():
    with pytest.raises(TypeError, match="dictionary"):
        predict_flow([1.0, 2.0])
