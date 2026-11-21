from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from collector.flow.aggregator import PacketRecord


def parse_packet(packet: Packet) -> PacketRecord | None:
    """Convert a Scapy packet into metadata-only flow information."""

    try:
        # Network layer
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

        packet_length = int(len(network_layer))

        if packet_length <= 0:
            return None

        # Defaults
        source_port = 0
        destination_port = 0

        tcp_flags: frozenset[str] = frozenset()
        tcp_window = 0

        transport_header_length = 0
        transport_layer = None

        # TCP
        if TCP in packet:
            transport_layer = packet[TCP]
            protocol = "TCP"

            source_port = int(transport_layer.sport)
            destination_port = int(transport_layer.dport)
            tcp_window = int(transport_layer.window)

            transport_header_length = (
                int(transport_layer.dataofs or 5) * 4
            )

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
                if flag in str(transport_layer.flags)
            )

        # UDP
        elif UDP in packet:
            transport_layer = packet[UDP]
            protocol = "UDP"

            source_port = int(transport_layer.sport)
            destination_port = int(transport_layer.dport)

            transport_header_length = 8

        # ICMP / ICMPv6
        elif ICMP in packet or any(
            layer.__name__.startswith("ICMPv6")
            for layer in packet.layers()
        ):
            protocol = "ICMP"

            if ICMP in packet:
                transport_layer = packet[ICMP]
            else:
                icmpv6_layer_class = next(
                    layer
                    for layer in packet.layers()
                    if layer.__name__.startswith("ICMPv6")
                )

                transport_layer = packet.getlayer(
                    icmpv6_layer_class
                )

            transport_header_length = 8

        # Other protocols
        else:
            protocol = "OTHER"

        # Header and payload lengths
        if transport_layer is not None:
            payload_length = int(len(transport_layer.payload))

            # Accounts for IPv6 extension headers as well.
            header_length = packet_length - payload_length

        else:
            header_length = ip_header_length

            if header_length > packet_length:
                return None

            payload_length = packet_length - header_length

        # Validate lengths
        if (
            payload_length < 0
            or header_length < 0
            or transport_header_length > header_length
            or transport_header_length < 0
        ):
            return None

        # Create packet record
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

    except (
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
        StopIteration,
    ):
        return None
