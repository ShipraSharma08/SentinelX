
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


def test_initial_tcp_window_backward_is_not_overwritten_by_subsequent_packets():
    aggregator = FlowAggregator()

    # Forward SYN packet with window 64240
    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        packet_length=74,
        timestamp=1.0,
        tcp_flags=frozenset({"SYN"}),
        tcp_window=64240,
    ))

    # First backward packet (e.g. SYN-ACK) with initial window 65535
    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=443,
        destination_port=50000,
        protocol="TCP",
        packet_length=74,
        timestamp=1.05,
        tcp_flags=frozenset({"SYN", "ACK"}),
        tcp_window=65535,
    ))

    # Forward ACK with window update (should not overwrite initial forward window)
    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        packet_length=66,
        timestamp=1.06,
        tcp_flags=frozenset({"ACK"}),
        tcp_window=1024,
    ))

    # Subsequent backward data / ACK packets with different window sizes (e.g. 500)
    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=443,
        destination_port=50000,
        protocol="TCP",
        packet_length=1500,
        timestamp=1.1,
        tcp_flags=frozenset({"ACK"}),
        tcp_window=500,
    ))

    # Subsequent backward teardown packet with small window (realistic case: window 16)
    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=443,
        destination_port=50000,
        protocol="TCP",
        packet_length=66,
        timestamp=1.2,
        tcp_flags=frozenset({"FIN", "ACK"}),
        tcp_window=16,
    ))

    record = aggregator.flush_all()[0]

    # Forward window must remain 64240 (not overwritten by 1024)
    assert record["init_win_bytes_forward"] == 64240

    # Backward window must remain 65535 (first packet window, not overwritten by 500 or 16)
    assert record["init_win_bytes_backward"] == 65535


def test_non_tcp_initial_windows_remain_none():
    aggregator = FlowAggregator()

    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=53,
        protocol="UDP",
        packet_length=100,
        timestamp=1.0,
    ))
    aggregator.ingest(PacketRecord(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=53,
        destination_port=50000,
        protocol="UDP",
        packet_length=100,
        timestamp=1.1,
    ))

    record = aggregator.flush_all()[0]

    assert record["init_win_bytes_forward"] is None
    assert record["init_win_bytes_backward"] is None


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


def test_min_seg_size_forward_tcp_regression():
    aggregator = FlowAggregator()

    packet1 = PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        packet_length=100,
        timestamp=1.0,
        header_length=40,
        payload_length=60,
    )
    packet2 = PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        packet_length=100,
        timestamp=2.0,
        header_length=32,
        payload_length=68,
    )

    aggregator.ingest(packet1)
    aggregator.ingest(packet2)

    record = aggregator.flush_all()[0]
    assert record["min_seg_size_forward"] == 32


def test_min_seg_size_forward_udp_regression():
    aggregator = FlowAggregator()

    packet = PacketRecord(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=53,
        protocol="UDP",
        packet_length=100,
        timestamp=1.0,
        header_length=28,
        payload_length=72,
    )

    aggregator.ingest(packet)

    record = aggregator.flush_all()[0]
    assert record["min_seg_size_forward"] == 28


def test_single_packet_flow_expires_on_flow_timeout_and_is_emitted():
    # Set idle_timeout high so expiration is triggered strictly by flow_timeout
    aggregator = FlowAggregator(flow_timeout=5.0, idle_timeout=60.0)

    packet1 = make_packet(timestamp=1.0)
    assert aggregator.ingest(packet1) == []
    assert len(aggregator.active_flows) == 1

    # Packet for the same flow arriving after flow_timeout
    packet2 = make_packet(timestamp=7.0)
    expired = aggregator.ingest(packet2)

    # 1. Single-packet flow is emitted when expiring due to flow_timeout
    assert len(expired) == 1
    assert expired[0]["packets"] == 1
    assert expired[0]["first_seen"] == 1.0
    assert expired[0]["last_seen"] == 1.0

    # 2. Expired flow is removed from active flows, replaced by new flow
    assert len(aggregator.active_flows) == 1
    active_flow = next(iter(aggregator.active_flows.values()))
    assert active_flow.first_seen == 7.0
    assert active_flow.total_packets == 1


def test_packet_record_accepts_cwr_and_cwe_flags():
    pkt_cwr = make_packet(tcp_flags=frozenset({"CWR"}))
    assert "CWR" in pkt_cwr.tcp_flags

    pkt_cwe = make_packet(tcp_flags=frozenset({"CWE"}))
    assert "CWR" in pkt_cwe.tcp_flags

