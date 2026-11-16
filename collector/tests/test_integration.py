
from scapy.layers.inet import IP, TCP
from scapy.packet import raw, Raw

from collector.capture.parser import parse_packet
from collector.flow.aggregator import FlowAggregator


def make_scapy_tcp_packet(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    timestamp,
    flags,
    payload=b"",
    window=4096,
):
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags=flags,
            window=window,
        )
    )

    if payload:
        packet = packet / Raw(load=payload)

    packet.time = timestamp

    # Ensure Scapy calculates actual packet lengths and header fields.
    packet = packet.__class__(raw(packet))
    packet.time = timestamp

    return packet


def test_scapy_packets_are_parsed_and_aggregated_into_one_bidirectional_flow():
    aggregator = FlowAggregator()

    forward_packet = make_scapy_tcp_packet(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=50000,
        destination_port=80,
        timestamp=1.0,
        flags="PA",
        payload=b"request-data",
        window=4096,
    )

    backward_packet = make_scapy_tcp_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        source_port=80,
        destination_port=50000,
        timestamp=2.0,
        flags="PA",
        payload=b"response-data",
        window=8192,
    )

    parsed_forward = parse_packet(forward_packet)
    parsed_backward = parse_packet(backward_packet)

    assert parsed_forward is not None
    assert parsed_backward is not None

    assert parsed_forward.transport_header_length == 20
    assert parsed_backward.transport_header_length == 20

    assert parsed_forward.payload_length == len(b"request-data")
    assert parsed_backward.payload_length == len(b"response-data")

    aggregator.ingest(parsed_forward)
    aggregator.ingest(parsed_backward)

    records = aggregator.flush_all()

    assert len(records) == 1

    record = records[0]

    assert record["protocol"] == "TCP"
    assert record["forward_packets"] == 1
    assert record["backward_packets"] == 1
    assert record["packets"] == 2

    assert record["forward_payload_bytes"] == len(b"request-data")
    assert record["backward_payload_bytes"] == len(b"response-data")

    assert record["forward_transport_header_length"] == 20
    assert record["backward_transport_header_length"] == 20

    assert record["forward_tcp_flags"]["PSH"] == 1
    assert record["forward_tcp_flags"]["ACK"] == 1
    assert record["backward_tcp_flags"]["PSH"] == 1
    assert record["backward_tcp_flags"]["ACK"] == 1

    assert record["act_data_pkt_fwd"] == 1
    assert record["min_seg_size_forward"] == 20

    assert record["duration"] == 1.0
    assert record["flow_iat"]["count"] == 1

    # Payload bytes are counted, but payload content is never retained.
    assert not hasattr(parsed_forward, "payload")
    assert not hasattr(parsed_backward, "payload")
