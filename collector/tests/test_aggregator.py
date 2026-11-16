
import pytest

from collector.flow.aggregator import FlowAggregator, PacketRecord


def make_packet(
    source_ip="192.168.1.10",
    destination_ip="192.168.1.20",
    source_port=50000,
    destination_port=80,
    protocol="TCP",
    packet_length=100,
    timestamp=1.0,
    tcp_flags=frozenset(),
):
    return PacketRecord(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_length=packet_length,
        timestamp=timestamp,
        tcp_flags=tcp_flags,
    )


def test_forward_and_backward_packets_are_aggregated():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(packet_length=100, timestamp=1.0))

    aggregator.ingest(make_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        packet_length=200,
        timestamp=2.0,
    ))

    record = aggregator.flush_all()[0]

    assert record["forward_packets"] == 1
    assert record["backward_packets"] == 1
    assert record["forward_bytes"] == 100
    assert record["backward_bytes"] == 200
    assert record["packets"] == 2
    assert record["duration"] == 1.0


def test_flow_uses_bidirectional_key():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(timestamp=1.0))

    aggregator.ingest(make_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        timestamp=2.0,
    ))

    assert len(aggregator.active_flows) == 1


def test_idle_flow_expires():
    aggregator = FlowAggregator(idle_timeout=10.0)

    aggregator.ingest(make_packet(timestamp=1.0))

    expired = aggregator.flush_expired(11.0)

    assert len(expired) == 1
    assert expired[0]["packets"] == 1
    assert len(aggregator.active_flows) == 0


def test_different_protocols_create_separate_flows():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(
        protocol="TCP",
        timestamp=1.0,
    ))

    aggregator.ingest(make_packet(
        protocol="UDP",
        timestamp=2.0,
    ))

    assert len(aggregator.active_flows) == 2


def test_tcp_flags_are_counted():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(
        timestamp=1.0,
        tcp_flags=frozenset({"SYN", "ACK"}),
    ))

    record = aggregator.flush_all()[0]

    assert record["tcp_flags"]["SYN"] == 1
    assert record["tcp_flags"]["ACK"] == 1


def test_flush_all_returns_and_clears_flows():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(timestamp=1.0))

    records = aggregator.flush_all()

    assert len(records) == 1
    assert len(aggregator.active_flows) == 0


def test_invalid_ip_is_rejected():
    with pytest.raises(ValueError):
        make_packet(source_ip="invalid-ip")


def test_negative_packet_length_is_rejected():
    with pytest.raises(ValueError):
        make_packet(packet_length=-1)


def test_directional_header_lengths():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(timestamp=1.0))
    aggregator.ingest(make_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        timestamp=2.0,
    ))

    record = aggregator.flush_all()[0]

    assert record["forward_header_length"] == 0
    assert record["backward_header_length"] == 0


def test_initial_tcp_windows_are_recorded():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(timestamp=1.0))
    aggregator.ingest(make_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        timestamp=2.0,
    ))

    record = aggregator.flush_all()[0]

    assert record["init_win_bytes_forward"] == 0
    assert record["init_win_bytes_backward"] == 0


def test_forward_data_packet_count():
    aggregator = FlowAggregator()

    packet = PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        packet_length=150,
        timestamp=1.0,
        header_length=40,
        payload_length=110,
    )

    aggregator.ingest(packet)
    record = aggregator.flush_all()[0]

    assert record["act_data_pkt_fwd"] == 1
    assert record["min_seg_size_forward"] == 40


def test_directional_tcp_flags():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(
        timestamp=1.0,
        tcp_flags=frozenset({"SYN"}),
    ))

    aggregator.ingest(make_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        timestamp=2.0,
        tcp_flags=frozenset({"SYN", "ACK"}),
    ))

    record = aggregator.flush_all()[0]

    assert record["forward_tcp_flags"]["SYN"] == 1
    assert record["backward_tcp_flags"]["SYN"] == 1
    assert record["backward_tcp_flags"]["ACK"] == 1


def test_flow_packet_length_statistics():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(packet_length=100, timestamp=1.0))
    aggregator.ingest(make_packet(packet_length=200, timestamp=2.0))
    aggregator.ingest(make_packet(packet_length=300, timestamp=3.0))

    record = aggregator.flush_all()[0]
    stats = record["forward_lengths"]

    assert stats["count"] == 3
    assert stats["min"] == 100
    assert stats["max"] == 300
    assert stats["mean"] == 200
    assert stats["variance"] == pytest.approx(6666.6666667)


def test_flow_and_directional_inter_arrival_times():
    aggregator = FlowAggregator()

    aggregator.ingest(make_packet(timestamp=1.0))
    aggregator.ingest(make_packet(timestamp=2.0))
    aggregator.ingest(make_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        timestamp=4.0,
    ))
    aggregator.ingest(make_packet(timestamp=7.0))

    record = aggregator.flush_all()[0]

    assert record["flow_iat"]["count"] == 3
    assert record["flow_iat"]["mean"] == pytest.approx(2.0)

    assert record["forward_iat"]["count"] == 2
    assert record["forward_iat"]["mean"] == pytest.approx(3.0)

    assert record["backward_iat"]["count"] == 0


def test_flow_statistics_retain_no_packet_history():
    aggregator = FlowAggregator(flow_timeout=2000.0)

    for timestamp in range(1, 1001):
        aggregator.ingest(
            make_packet(
                packet_length=100 + timestamp % 100,
                timestamp=float(timestamp),
            )
        )

    flow = next(iter(aggregator.active_flows.values()))

    assert flow.forward_packets == 1000
    assert not hasattr(flow, "packet_metadata")
    assert not hasattr(flow, "packet_timestamps")


def test_active_flow_capacity_rejects_new_flows():
    from collector.flow.aggregator import FlowCapacityError

    aggregator = FlowAggregator(max_active_flows=1)
    aggregator.ingest(make_packet(timestamp=1.0))

    second_flow = make_packet(
        destination_ip="192.168.1.30",
        timestamp=2.0,
    )

    with pytest.raises(FlowCapacityError):
        aggregator.ingest(second_flow)

    assert len(aggregator.active_flows) == 1
    assert aggregator.rejected_new_flow_packets == 1


def test_existing_flow_continues_when_capacity_is_full():
    aggregator = FlowAggregator(max_active_flows=1)

    aggregator.ingest(make_packet(timestamp=1.0))
    aggregator.ingest(make_packet(timestamp=2.0))

    assert len(aggregator.active_flows) == 1
    assert aggregator.rejected_new_flow_packets == 0

    flow = next(iter(aggregator.active_flows.values()))
    assert flow.forward_packets == 2


def test_expired_flow_frees_capacity():
    aggregator = FlowAggregator(
        idle_timeout=5.0,
        max_active_flows=1,
    )

    aggregator.ingest(make_packet(timestamp=1.0))

    second_flow = make_packet(
        destination_ip="192.168.1.30",
        timestamp=7.0,
    )

    expired = aggregator.ingest(second_flow)

    assert len(expired) == 1
    assert expired[0]["packets"] == 1
    assert len(aggregator.active_flows) == 1
    assert aggregator.rejected_new_flow_packets == 0


def test_invalid_active_flow_capacity_is_rejected():
    with pytest.raises(ValueError):
        FlowAggregator(max_active_flows=0)

    with pytest.raises(ValueError):
        FlowAggregator(max_active_flows=-1)

    with pytest.raises(ValueError):
        FlowAggregator(max_active_flows=1.5)
