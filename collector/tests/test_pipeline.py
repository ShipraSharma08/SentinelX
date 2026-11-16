
from unittest.mock import Mock

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw, raw

from collector.backend.ml_client import (
    MLInferenceError,
    MLPrediction,
)
from collector.backend.pipeline import NetworkFlowPipeline


def make_packet(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    timestamp,
    flags,
    payload,
):
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags=flags,
            window=64240,
        )
        / Raw(load=payload)
    )

    packet = IP(raw(packet))
    packet.time = timestamp
    return packet


@pytest.fixture
def ml_client():
    client = Mock()
    client.predict.return_value = MLPrediction(
        prediction="BENIGN",
        attack_probability=0.02,
        model="web_coverage_candidate",
    )
    return client


@pytest.fixture
def pipeline(ml_client):
    return NetworkFlowPipeline(ml_client=ml_client)


def test_packets_are_aggregated_without_early_prediction(
    pipeline,
    ml_client,
):
    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )

    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    assert pipeline.process_packet(first) == []
    assert pipeline.process_packet(second) == []

    ml_client.predict.assert_not_called()
    assert len(pipeline.aggregator.active_flows) == 1


def test_flush_all_runs_inference_for_completed_flow(
    pipeline,
    ml_client,
):
    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )

    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)

    results = pipeline.flush_all()

    assert len(results) == 1
    assert results[0]["status"] == "success"
    assert results[0]["prediction"] == "BENIGN"
    assert results[0]["attack_probability"] == 0.02
    assert results[0]["model"] == "web_coverage_candidate"

    assert ml_client.predict.call_count == 1

    features = ml_client.predict.call_args.args[0]
    assert len(features) == 70


def test_pipeline_returns_flow_metadata(pipeline):
    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )

    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)

    result = pipeline.flush_all()[0]
    flow = result["flow"]

    assert flow["protocol"] == "TCP"
    assert flow["packets"] == 2
    assert flow["duration"] == pytest.approx(0.5)


def test_expired_flow_is_sent_for_inference(
    ml_client,
):
    pipeline = NetworkFlowPipeline(
        aggregator=__import__(
            "collector.flow.aggregator",
            fromlist=["FlowAggregator"],
        ).FlowAggregator(idle_timeout=1.0),
        ml_client=ml_client,
    )

    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )

    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)

    results = pipeline.flush_expired(2.5)

    assert len(results) == 1
    assert results[0]["status"] == "success"
    assert ml_client.predict.call_count == 1


def test_unsupported_packet_is_ignored(
    pipeline,
    ml_client,
):
    from scapy.layers.l2 import Ether

    result = pipeline.process_packet(
        Ether(dst="ff:ff:ff:ff:ff:ff")
    )

    assert result == []
    assert pipeline.packets_ignored == 1
    ml_client.predict.assert_not_called()


def test_ml_failure_is_reported_without_crashing(
    pipeline,
    ml_client,
):
    ml_client.predict.side_effect = MLInferenceError(
        "Unable to communicate with the ML inference service"
    )

    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )

    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)

    results = pipeline.flush_all()

    assert len(results) == 1
    assert results[0]["status"] == "inference_failed"
    assert "features" in results[0]
    assert len(results[0]["features"]) == 70
    assert pipeline.predictions_failed == 1
    assert pipeline.predictions_succeeded == 0


def test_pipeline_status_tracks_processing(pipeline):
    packet = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )

    pipeline.process_packet(packet)

    status = pipeline.get_status()

    assert status["packets_processed"] == 1
    assert status["packets_ignored"] == 0
    assert status["active_flows"] == 1
    assert status["flows_completed"] == 0
    assert status["predictions_succeeded"] == 0
    assert status["predictions_failed"] == 0

from collector.backend.backend_client import (
    BackendPersistenceError,
    BackendPersistenceResult,
)


def test_successful_prediction_is_persisted_to_backend(ml_client):
    backend_client = Mock()
    backend_client.persist.return_value = BackendPersistenceResult(
        flow_id=101,
        prediction_id=201,
        source_asset_id=301,
        destination_asset_id=302,
        status="SAVED",
    )

    pipeline = NetworkFlowPipeline(
        ml_client=ml_client,
        backend_client=backend_client,
    )

    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )
    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)
    results = pipeline.flush_all()

    assert len(results) == 1
    assert results[0]["status"] == "success"
    assert results[0]["persistence"] == {
        "status": "SAVED",
        "flow_id": 101,
        "prediction_id": 201,
        "source_asset_id": 301,
        "destination_asset_id": 302,
    }

    backend_client.persist.assert_called_once()

    payload = backend_client.persist.call_args.args[0]

    assert payload["source_ip"] == "192.168.1.10"
    assert payload["destination_ip"] == "192.168.1.20"
    assert payload["protocol"] == "TCP"
    assert payload["prediction"] == "BENIGN"
    assert payload["attack_probability"] == 0.02

    status = pipeline.get_status()
    assert status["persistence_succeeded"] == 1
    assert status["persistence_failed"] == 0


def test_backend_failure_does_not_crash_pipeline(ml_client):
    backend_client = Mock()
    backend_client.persist.side_effect = BackendPersistenceError(
        "Backend unavailable"
    )

    pipeline = NetworkFlowPipeline(
        ml_client=ml_client,
        backend_client=backend_client,
    )

    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )
    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)
    results = pipeline.flush_all()

    assert len(results) == 1
    assert results[0]["status"] == "success"
    assert results[0]["persistence"]["status"] == "failed"
    assert results[0]["persistence"]["error"] == "Backend unavailable"

    status = pipeline.get_status()
    assert status["predictions_succeeded"] == 1
    assert status["persistence_succeeded"] == 0
    assert status["persistence_failed"] == 1


def test_ml_failure_does_not_call_backend(ml_client):
    backend_client = Mock()
    ml_client.predict.side_effect = MLInferenceError(
        "ML service unavailable"
    )

    pipeline = NetworkFlowPipeline(
        ml_client=ml_client,
        backend_client=backend_client,
    )

    first = make_packet(
        "192.168.1.10",
        "192.168.1.20",
        50000,
        80,
        1.0,
        "S",
        b"hello",
    )
    second = make_packet(
        "192.168.1.20",
        "192.168.1.10",
        80,
        50000,
        1.5,
        "PA",
        b"world",
    )

    pipeline.process_packet(first)
    pipeline.process_packet(second)
    results = pipeline.flush_all()

    assert len(results) == 1
    assert results[0]["status"] == "inference_failed"

    backend_client.persist.assert_not_called()

    status = pipeline.get_status()
    assert status["predictions_failed"] == 1
    assert status["persistence_succeeded"] == 0
    assert status["persistence_failed"] == 0
