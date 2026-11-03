import pytest
from fastapi.testclient import TestClient

from ml.api import main


@pytest.fixture
def client():
    return TestClient(main.app)


def test_health_returns_healthy_when_model_is_ready(client, monkeypatch):
    monkeypatch.setattr(main, "_load_model", lambda: (object(), ["feature"]))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "model_ready": True,
        "service": "sentinelx-ml",
    }


def test_health_returns_503_when_model_is_missing(client, monkeypatch):
    def raise_missing_model():
        raise FileNotFoundError("internal model path")

    monkeypatch.setattr(main, "_load_model", raise_missing_model)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["detail"] == "Trained ML model is unavailable."
    assert "internal model path" not in response.text


def test_health_returns_503_when_model_cannot_be_loaded(client, monkeypatch):
    def raise_load_error():
        raise RuntimeError("internal load details")

    monkeypatch.setattr(main, "_load_model", raise_load_error)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["detail"] == "ML model could not be loaded."
    assert "internal load details" not in response.text


def test_predict_returns_prediction(client, monkeypatch):
    expected = {
        "prediction": "ATTACK",
        "attack_probability": 0.91,
        "model": "web_coverage_candidate",
    }
    monkeypatch.setattr(main, "predict_flow", lambda features: expected)

    response = client.post("/predict", json={"features": {"Flow Duration": 1.0}})

    assert response.status_code == 200
    assert response.json() == expected


def test_predict_returns_422_for_invalid_features(client, monkeypatch):
    def raise_invalid_features(features):
        raise ValueError("Feature mismatch")

    monkeypatch.setattr(main, "predict_flow", raise_invalid_features)

    response = client.post("/predict", json={"features": {"unexpected": 1.0}})

    assert response.status_code == 422
    assert response.json()["detail"] == "Feature mismatch"


def test_predict_returns_503_when_model_is_missing(client, monkeypatch):
    def raise_missing_model(features):
        raise FileNotFoundError("internal model path")

    monkeypatch.setattr(main, "predict_flow", raise_missing_model)

    response = client.post("/predict", json={"features": {"Flow Duration": 1.0}})

    assert response.status_code == 503
    assert response.json()["detail"] == "Trained ML model is unavailable."
    assert "internal model path" not in response.text


def test_predict_returns_500_without_exposing_internal_error(client, monkeypatch):
    def raise_unexpected_error(features):
        raise RuntimeError("internal prediction details")

    monkeypatch.setattr(main, "predict_flow", raise_unexpected_error)

    response = client.post("/predict", json={"features": {"Flow Duration": 1.0}})

    assert response.status_code == 500
    assert response.json()["detail"] == "Prediction failed unexpectedly."
    assert "internal prediction details" not in response.text


def test_predict_rejects_non_numeric_feature(client):
    response = client.post("/predict", json={"features": {"Flow Duration": "not-a-number"}})

    assert response.status_code == 422


def test_predict_rejects_missing_features_field(client):
    response = client.post("/predict", json={})

    assert response.status_code == 422
