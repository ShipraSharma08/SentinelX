
import json
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from collector.backend.ml_client import (
    MLInferenceClient,
    MLInferenceError,
    MLPrediction,
)
from collector.features.extractor import FEATURE_NAMES


def valid_features():
    return {name: 0.0 for name in FEATURE_NAMES}


class FakeResponse:
    def __init__(self, data, status=200):
        self.data = data
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return json.dumps(self.data).encode("utf-8")


def valid_response():
    return {
        "prediction": "ATTACK",
        "attack_probability": 0.95,
        "model": "web_coverage_candidate",
    }


@pytest.fixture
def client():
    return MLInferenceClient(
        predict_url="http://127.0.0.1:8000/predict",
        timeout=5,
    )


def test_successful_attack_prediction(client):
    with patch(
        "collector.backend.ml_client.urlopen",
        return_value=FakeResponse(valid_response()),
    ):
        result = client.predict(valid_features())

    assert isinstance(result, MLPrediction)
    assert result.prediction == "ATTACK"
    assert result.attack_probability == 0.95
    assert result.model == "web_coverage_candidate"


def test_successful_benign_prediction(client):
    response = {
        "prediction": "BENIGN",
        "attack_probability": 0.02,
        "model": "web_coverage_candidate",
    }

    with patch(
        "collector.backend.ml_client.urlopen",
        return_value=FakeResponse(response),
    ):
        result = client.predict(valid_features())

    assert result.prediction == "BENIGN"
    assert result.attack_probability == 0.02


def test_missing_feature_is_rejected(client):
    features = valid_features()
    del features[FEATURE_NAMES[0]]

    with pytest.raises(MLInferenceError, match="Feature names or order"):
        client.predict(features)


def test_wrong_feature_order_is_rejected(client):
    features = valid_features()
    reversed_features = dict(reversed(list(features.items())))

    with pytest.raises(MLInferenceError, match="Feature names or order"):
        client.predict(reversed_features)


def test_non_finite_feature_is_rejected(client):
    features = valid_features()
    features[FEATURE_NAMES[0]] = float("nan")

    with pytest.raises(MLInferenceError, match="must be finite"):
        client.predict(features)


def test_invalid_prediction_label_is_rejected(client):
    response = valid_response()
    response["prediction"] = "UNKNOWN"

    with patch(
        "collector.backend.ml_client.urlopen",
        return_value=FakeResponse(response),
    ):
        with pytest.raises(MLInferenceError, match="unsupported prediction"):
            client.predict(valid_features())


def test_invalid_probability_is_rejected(client):
    response = valid_response()
    response["attack_probability"] = 1.5

    with patch(
        "collector.backend.ml_client.urlopen",
        return_value=FakeResponse(response),
    ):
        with pytest.raises(MLInferenceError, match="invalid attack probability"):
            client.predict(valid_features())


def test_missing_model_name_is_rejected(client):
    response = valid_response()
    response["model"] = ""

    with patch(
        "collector.backend.ml_client.urlopen",
        return_value=FakeResponse(response),
    ):
        with pytest.raises(MLInferenceError, match="invalid model name"):
            client.predict(valid_features())


def test_invalid_json_response_is_rejected(client):
    class InvalidJSONResponse(FakeResponse):
        def read(self):
            return b"not valid json"

    with patch(
        "collector.backend.ml_client.urlopen",
        return_value=InvalidJSONResponse({}),
    ):
        with pytest.raises(MLInferenceError, match="invalid JSON"):
            client.predict(valid_features())


def test_http_error_is_handled_safely(client):
    error = HTTPError(
        url=client.predict_url,
        code=503,
        msg="Service Unavailable",
        hdrs=None,
        fp=None,
    )

    with patch(
        "collector.backend.ml_client.urlopen",
        side_effect=error,
    ):
        with pytest.raises(MLInferenceError, match="HTTP 503"):
            client.predict(valid_features())


def test_timeout_is_handled_safely(client):
    with patch(
        "collector.backend.ml_client.urlopen",
        side_effect=TimeoutError("Connection timed out"),
    ):
        with pytest.raises(
            MLInferenceError,
            match="Unable to communicate",
        ):
            client.predict(valid_features())


def test_invalid_timeout_is_rejected():
    with pytest.raises(ValueError, match="Timeout"):
        MLInferenceClient(timeout=0)


def test_non_finite_timeout_is_rejected():
    with pytest.raises(ValueError, match="Timeout"):
        MLInferenceClient(timeout=float("inf"))
