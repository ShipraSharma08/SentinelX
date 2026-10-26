import pytest

from ml.inference.predict import predict_flow, _load_model


@pytest.fixture(scope="module")
def valid_features():
    model, feature_names = _load_model()
    return {feature: 0.0 for feature in feature_names}


def test_prediction_returns_expected_structure(valid_features):
    result = predict_flow(valid_features)
    assert set(result.keys()) == {
        "prediction",
        "attack_probability",
        "model",
    }


def test_prediction_has_valid_class(valid_features):
    result = predict_flow(valid_features)
    assert result["prediction"] in {"BENIGN", "ATTACK"}


def test_attack_probability_is_valid(valid_features):
    result = predict_flow(valid_features)
    assert 0.0 <= result["attack_probability"] <= 1.0


def test_model_name_is_correct(valid_features):
    result = predict_flow(valid_features)
    assert result["model"] == "baseline_logistic_regression"


def test_missing_feature_is_rejected(valid_features):
    valid_features.pop(next(iter(valid_features)))
    with pytest.raises(ValueError, match="Feature mismatch"):
        predict_flow(valid_features)


def test_unexpected_feature_is_rejected(valid_features):
    valid_features["unexpected_feature"] = 1.0
    with pytest.raises(ValueError, match="Feature mismatch"):
        predict_flow(valid_features)
