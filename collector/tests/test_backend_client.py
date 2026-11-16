
import json
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from collector.backend.backend_client import (
    BackendPersistenceClient,
    BackendPersistenceError,
)


@pytest.fixture
def valid_payload():
    return {
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "source_port": 51514,
        "destination_port": 443,
        "protocol": "TCP",
        "bytes_sent": 1500,
        "bytes_received": 4200,
        "packets": 12,
        "duration": 2.5,
        "first_seen": 1794656100.0,
        "prediction": "BENIGN",
        "attack_probability": 0.08,
        "model": "test-model",
    }


@pytest.fixture
def successful_response():
    return {
        "flowId": 10,
        "predictionId": 20,
        "sourceAssetId": 1,
        "destinationAssetId": 2,
        "prediction": "BENIGN",
        "attackProbability": 0.08,
        "model": "test-model",
        "timestamp": "2026-11-14T11:35:21Z",
        "status": "SAVED",
    }


def make_http_response(data, status=201):
    response = MagicMock()
    response.status = status
    response.read.return_value = json.dumps(data).encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = None
    return response


def test_successful_backend_persistence(
    valid_payload,
    successful_response,
):
    client = BackendPersistenceClient(
        ingest_url="http://127.0.0.1:8080/api/collector/flows",
        api_key="test-secret",
    )

    with patch(
        "collector.backend.backend_client.urlopen",
        return_value=make_http_response(successful_response),
    ) as mock_urlopen:
        result = client.persist(valid_payload)

    assert result.status == "SAVED"
    assert result.flow_id == 10
    assert result.prediction_id == 20
    assert result.source_asset_id == 1
    assert result.destination_asset_id == 2

    request = mock_urlopen.call_args.args[0]

    assert request.get_method() == "POST"
    assert request.get_header("X-collector-key") == "test-secret"

    sent_payload = json.loads(request.data.decode("utf-8"))
    assert sent_payload == valid_payload


def test_missing_api_key_is_rejected(valid_payload):
    client = BackendPersistenceClient(api_key="")

    with pytest.raises(
        BackendPersistenceError,
        match="API key is not configured",
    ):
        client.persist(valid_payload)


def test_invalid_payload_is_rejected():
    client = BackendPersistenceClient(api_key="test-secret")

    with pytest.raises(
        BackendPersistenceError,
        match="missing required fields",
    ):
        client.persist({})


def test_backend_http_error_is_handled(valid_payload):
    client = BackendPersistenceClient(api_key="test-secret")

    error = HTTPError(
        url="http://127.0.0.1:8080/api/collector/flows",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=BytesIO(b"Unauthorized"),
    )

    with patch(
        "collector.backend.backend_client.urlopen",
        side_effect=error,
    ):
        with pytest.raises(
            BackendPersistenceError,
            match="HTTP 401",
        ):
            client.persist(valid_payload)


def test_invalid_backend_response_is_rejected(valid_payload):
    client = BackendPersistenceClient(api_key="test-secret")

    invalid_response = {
        "flowId": 10,
        "status": "FAILED",
    }

    with patch(
        "collector.backend.backend_client.urlopen",
        return_value=make_http_response(invalid_response),
    ):
        with pytest.raises(
            BackendPersistenceError,
            match="did not confirm flow persistence",
        ):
            client.persist(valid_payload)
