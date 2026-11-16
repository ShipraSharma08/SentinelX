
from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from collector.flow.aggregator import PacketRecord


def parse_packet(packet: Packet) -> PacketRecord | None:
    """Convert a Scapy packet into metadata-only flow information."""

    try:
        if IP in packet:
            network_layer = packet[IP]
            source_ip = network_layer.src
            destination_ip = network_layer.dst
            ip_header_length = int(network_layer.ihl or 5) * 4

        elif IPv6 in packet:
            network_layer = packet[IPv6]
            source_ip = network_layer.src
            destination_ip = network_layer.dst
            ip_header_length = 40

        else:
            return None

        source_port = 0
        destination_port = 0
        tcp_flags: frozenset[str] = frozenset()
        tcp_window = 0
        transport_header_length = 0

        if TCP in packet:
            transport = packet[TCP]
            protocol = "TCP"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            tcp_window = int(transport.window)
            transport_header_length = int(transport.dataofs or 5) * 4

            flag_names = {
                "F": "FIN",
                "S": "SYN",
                "R": "RST",
                "P": "PSH",
                "A": "ACK",
                "U": "URG",
                "E": "ECE",
                "C": "CWR",
            }

            tcp_flags = frozenset(
                name
                for flag, name in flag_names.items()
                if flag in str(transport.flags)
            )

        elif UDP in packet:
            transport = packet[UDP]
            protocol = "UDP"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            transport_header_length = 8

        elif ICMP in packet or any(
            layer.__name__.startswith("ICMPv6")
            for layer in packet.layers()
        ):
            protocol = "ICMP"
            transport_header_length = 8

        else:
            protocol = "OTHER"

        packet_length = int(len(packet))
        header_length = ip_header_length + transport_header_length

        if header_length > packet_length:
            return None

        payload_length = packet_length - header_length

        return PacketRecord(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_length=packet_length,
            timestamp=float(packet.time),
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            header_length=header_length,
            payload_length=payload_length,
            transport_header_length=transport_header_length,
        )

    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
