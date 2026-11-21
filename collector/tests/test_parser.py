from scapy.layers.l2 import Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrHopByHop,
    ICMPv6EchoRequest,
)
from scapy.packet import Raw

from collector.capture.parser import parse_packet


def test_parse_tcp_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="S", window=64240)
        / Raw(load=b"test-payload")
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "TCP"
    assert record.source_ip == "192.168.1.10"
    assert record.destination_ip == "192.168.1.20"
    assert record.source_port == 50000
    assert record.destination_port == 80
    assert "SYN" in record.tcp_flags
    assert record.tcp_window == 64240
    assert record.payload_length == len(b"test-payload")


def test_parse_udp_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=53000, dport=53)
        / Raw(load=b"dns-test")
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "UDP"
    assert record.source_port == 53000
    assert record.destination_port == 53
    assert record.payload_length == len(b"dns-test")


def test_parse_icmp_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP()
        / Raw(load=b"icmp-test")
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "ICMP"
    assert record.source_port == 0
    assert record.destination_port == 0


def test_parse_ipv6_tcp_packet():
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=50000, dport=443, flags="A")
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "TCP"
    assert record.source_ip == "2001:db8::1"
    assert record.destination_ip == "2001:db8::2"
    assert "ACK" in record.tcp_flags


def test_parse_ipv6_tcp_with_extension_header():
    payload = b"ipv6-extension-test"

    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IPv6ExtHdrHopByHop()
        / TCP(sport=50000, dport=443, flags="A")
        / Raw(load=payload)
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "TCP"
    assert record.source_ip == "2001:db8::1"
    assert record.destination_ip == "2001:db8::2"
    assert record.source_port == 50000
    assert record.destination_port == 443

    # Payload must only contain application payload.
    assert record.payload_length == len(payload)

    # Header length must include IPv6, extension and TCP headers.
    assert record.header_length > 40 + 20

    # Header + payload must account for the entire IP packet.
    assert record.header_length + record.payload_length == record.packet_length


def test_parse_ipv6_icmp_packet():
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / ICMPv6EchoRequest()
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "ICMP"


def test_parse_ethernet_udp_payload_length_excludes_ethernet_header():
    payload = b"x" * 188

    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=123, dport=123)
        / Raw(load=payload)
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "UDP"

    # Packet length should represent the IP packet,
    # not the complete Ethernet frame.
    assert record.packet_length == len(packet[IP])

    # Payload length must exclude Ethernet, IP and UDP headers.
    assert record.payload_length == len(payload)


def test_unsupported_packet_returns_none():
    packet = Raw(load=b"unsupported")

    assert parse_packet(packet) is None


def test_packet_payload_is_not_stored():
    secret_payload = b"private-test-data"

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443)
        / Raw(load=secret_payload)
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.payload_length == len(secret_payload)
    assert not hasattr(record, "payload")
    assert secret_payload.decode() not in str(record)
