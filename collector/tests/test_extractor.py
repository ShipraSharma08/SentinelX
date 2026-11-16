
import math

import pytest

from collector.flow.aggregator import FlowAggregator, PacketRecord
from collector.features.extractor import (
    FEATURE_NAMES,
    extract_features,
)


def build_flow():
    """Create a completed bidirectional TCP flow for testing."""
    aggregator = FlowAggregator()

    packets = [
        PacketRecord(
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            source_port=50000,
            destination_port=80,
            protocol="TCP",
            packet_length=100,
            timestamp=1.0,
            tcp_flags=frozenset({"SYN"}),
            tcp_window=64240,
            header_length=40,
            payload_length=60,
            transport_header_length=20,
        ),
        PacketRecord(
            source_ip="192.168.1.20",
            destination_ip="192.168.1.10",
            source_port=80,
            destination_port=50000,
            protocol="TCP",
            packet_length=120,
            timestamp=1.5,
            tcp_flags=frozenset({"ACK", "PSH"}),
            tcp_window=65535,
            header_length=40,
            payload_length=80,
            transport_header_length=20,
        ),
    ]

    for packet in packets:
        aggregator.ingest(packet)

    records = aggregator.flush_all()

    assert len(records) == 1
    return records[0]


@pytest.fixture
def flow_record():
    return build_flow()


@pytest.fixture
def features(flow_record):
    return extract_features(flow_record)


def test_extractor_returns_exactly_70_features(features):
    assert len(features) == 70


def test_extractor_matches_model_feature_order(features):
    assert tuple(features.keys()) == FEATURE_NAMES


def test_all_extracted_values_are_finite_floats(features):
    assert all(
        isinstance(value, float) and math.isfinite(value)
        for value in features.values()
    )


def test_destination_port(features):
    assert features["Destination Port"] == 80.0


def test_flow_duration_is_in_microseconds(features):
    assert features["Flow Duration"] == 500_000.0


def test_directional_packet_counts(features):
    assert features["Total Fwd Packets"] == 1.0
    assert features["Total Backward Packets"] == 1.0


def test_directional_payload_bytes(features):
    assert features["Total Length of Fwd Packets"] == 60.0
    assert features["Total Length of Bwd Packets"] == 80.0


def test_packet_length_statistics(features):
    assert features["Fwd Packet Length Mean"] == 60.0
    assert features["Bwd Packet Length Mean"] == 80.0
    assert features["Packet Length Mean"] == 70.0


def test_flow_iat_is_converted_to_microseconds(features):
    assert features["Flow IAT Mean"] == 500_000.0
    assert features["Flow IAT Min"] == 500_000.0
    assert features["Flow IAT Max"] == 500_000.0
    assert features["Flow IAT Std"] == 0.0


def test_directional_iat(features):
    assert features["Fwd IAT Total"] == 0.0
    assert features["Bwd IAT Total"] == 0.0


def test_tcp_flag_counts(features):
    assert features["SYN Flag Count"] == 1.0
    assert features["ACK Flag Count"] == 1.0
    assert features["PSH Flag Count"] == 1.0


def test_header_length_features(features):
    assert features["Fwd Header Length"] == 20.0
    assert features["Bwd Header Length"] == 20.0
    assert features["Fwd Header Length.1"] == 20.0


def test_average_packet_size(features):
    assert features["Average Packet Size"] == 70.0
    assert features["Avg Fwd Segment Size"] == 60.0
    assert features["Avg Bwd Segment Size"] == 80.0


def test_flow_rates(features):
    assert features["Flow Bytes/s"] == 280.0
    assert features["Flow Packets/s"] == 4.0
    assert features["Fwd Packets/s"] == 2.0
    assert features["Bwd Packets/s"] == 2.0


def test_initial_tcp_windows(features):
    assert features["Init_Win_bytes_forward"] == 64240.0
    assert features["Init_Win_bytes_backward"] == 65535.0


def test_subflow_features(features):
    assert features["Subflow Fwd Packets"] == 1.0
    assert features["Subflow Bwd Packets"] == 1.0
    assert features["Subflow Fwd Bytes"] == 60.0
    assert features["Subflow Bwd Bytes"] == 80.0


def test_missing_required_field_is_rejected(flow_record):
    del flow_record["destination_port"]

    with pytest.raises(ValueError, match="destination_port"):
        extract_features(flow_record)


def test_non_finite_flow_duration_is_rejected(flow_record):
    flow_record["duration"] = float("nan")

    with pytest.raises(ValueError, match="duration"):
        extract_features(flow_record)


def test_negative_flow_duration_is_rejected(flow_record):
    flow_record["duration"] = -1.0

    with pytest.raises(ValueError, match="negative"):
        extract_features(flow_record)


def test_non_mapping_input_is_rejected():
    with pytest.raises(TypeError, match="mapping"):
        extract_features(None)
