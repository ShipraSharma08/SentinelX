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