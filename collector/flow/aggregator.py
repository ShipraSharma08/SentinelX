
from __future__ import annotations

import ipaddress
import math
import uuid
from dataclasses import dataclass, field
from typing import Literal

from collector.flow.activity import FlowActivityTracker
from collector.flow.statistics import StreamingStatistics


Protocol = Literal["TCP", "UDP", "ICMP", "OTHER"]

TCP_FLAG_NAMES = {
    "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "CWE"
}


class FlowCapacityError(RuntimeError):
    """Raised when a new flow cannot be accepted due to capacity."""


@dataclass(frozen=True)
class PacketRecord:
    """Normalized packet metadata. Payload content is never retained."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: Protocol
    packet_length: int
    timestamp: float
    tcp_flags: frozenset[str] = frozenset()
    tcp_window: int = 0
    header_length: int = 0
    payload_length: int = 0
    transport_header_length: int = 0

    def __post_init__(self):
        ipaddress.ip_address(self.source_ip)
        ipaddress.ip_address(self.destination_ip)

        if self.protocol not in {"TCP", "UDP", "ICMP", "OTHER"}:
            raise ValueError("Unsupported protocol")

        if not 0 <= self.source_port <= 65535:
            raise ValueError("Invalid source port")

        if not 0 <= self.destination_port <= 65535:
            raise ValueError("Invalid destination port")

        if self.packet_length < 0:
            raise ValueError("Packet length cannot be negative")

        if not math.isfinite(self.timestamp) or self.timestamp < 0:
            raise ValueError("Invalid packet timestamp")

        if self.tcp_window < 0:
            raise ValueError("TCP window cannot be negative")

        if self.header_length < 0 or self.payload_length < 0:
            raise ValueError("Packet lengths cannot be negative")

        if self.transport_header_length < 0:
            raise ValueError("Transport header length cannot be negative")

        if self.transport_header_length > self.header_length:
            raise ValueError("Transport header exceeds total header length")

        if self.header_length + self.payload_length > self.packet_length:
            raise ValueError("Header and payload exceed packet length")

        normalized_flags = {
            "CWR" if flag.upper() == "CWE" else flag.upper()
            for flag in self.tcp_flags
        }

        if not normalized_flags.issubset(TCP_FLAG_NAMES):
            raise ValueError("Unsupported TCP flag")

        object.__setattr__(self, "tcp_flags", frozenset(normalized_flags))


@dataclass(frozen=True)
class FlowKey:
    """Direction-independent bidirectional flow key."""

    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    protocol: Protocol

    @classmethod
    def from_packet(cls, packet: PacketRecord) -> FlowKey:
        source = (packet.source_ip, packet.source_port)
        destination = (packet.destination_ip, packet.destination_port)
        endpoint_a, endpoint_b = sorted((source, destination))

        return cls(endpoint_a, endpoint_b, packet.protocol)


@dataclass
class FlowAccumulator:
    """Bounded-memory directional statistics for one network flow."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: Protocol

    first_seen: float
    last_seen: float

    # Stable unique identifier for this flow's entire lifecycle.
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    forward_packets: int = 0
    backward_packets: int = 0

    forward_bytes: int = 0
    backward_bytes: int = 0

    forward_header_length: int = 0
    backward_header_length: int = 0

    forward_lengths: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    backward_lengths: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    all_lengths: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )

    forward_payload_bytes: int = 0
    backward_payload_bytes: int = 0

    forward_payload_lengths: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    backward_payload_lengths: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    all_payload_lengths: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )

    forward_transport_header_length: int = 0
    backward_transport_header_length: int = 0

    flow_iat: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    forward_iat: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    backward_iat: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )

    last_forward_seen: float | None = None
    last_backward_seen: float | None = None

    tcp_flags: dict[str, int] = field(default_factory=dict)
    forward_tcp_flags: dict[str, int] = field(default_factory=dict)
    backward_tcp_flags: dict[str, int] = field(default_factory=dict)

    init_win_bytes_forward: int | None = None
    init_win_bytes_backward: int | None = None

    act_data_pkt_fwd: int = 0
    min_seg_size_forward: int | None = None

    activity_tracker: FlowActivityTracker = field(
        default_factory=FlowActivityTracker
    )

    @property
    def total_packets(self) -> int:
        return self.forward_packets + self.backward_packets

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    def add_packet(self, packet: PacketRecord) -> None:
        if packet.timestamp < self.last_seen:
            raise ValueError("Out-of-order packet timestamp")

        is_forward = (
            packet.source_ip == self.source_ip
            and packet.source_port == self.source_port
            and packet.destination_ip == self.destination_ip
            and packet.destination_port == self.destination_port
        )

        direction_flags = (
            self.forward_tcp_flags
            if is_forward
            else self.backward_tcp_flags
        )

        self.all_lengths.add(packet.packet_length)

        payload_length = (
            packet.payload_length
            if packet.protocol in {"TCP", "UDP"}
            else 0
        )

        self.all_payload_lengths.add(payload_length)

        # Activity and subflow tracking uses payload bytes.
        self.activity_tracker.add_packet(
            timestamp=packet.timestamp,
            is_forward=is_forward,
            packet_length=payload_length,
        )

        if self.total_packets > 0:
            self.flow_iat.add(packet.timestamp - self.last_seen)

        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet.packet_length
            self.forward_header_length += packet.header_length
            self.forward_lengths.add(packet.packet_length)

            self.forward_payload_bytes += payload_length
            self.forward_payload_lengths.add(payload_length)

            self.forward_transport_header_length += (
                packet.transport_header_length
            )

            if self.last_forward_seen is not None:
                self.forward_iat.add(
                    packet.timestamp - self.last_forward_seen
                )

            self.last_forward_seen = packet.timestamp

            if (
                packet.protocol == "TCP"
                and self.init_win_bytes_forward is None
            ):
                self.init_win_bytes_forward = packet.tcp_window

            if packet.protocol == "TCP" and payload_length > 0:
                self.act_data_pkt_fwd += 1

            if packet.header_length > 0:
                if self.min_seg_size_forward is None:
                    self.min_seg_size_forward = packet.header_length
                else:
                    self.min_seg_size_forward = min(
                        self.min_seg_size_forward,
                        packet.header_length,
                    )

        else:
            self.backward_packets += 1
            self.backward_bytes += packet.packet_length
            self.backward_header_length += packet.header_length
            self.backward_lengths.add(packet.packet_length)

            self.backward_payload_bytes += payload_length
            self.backward_payload_lengths.add(payload_length)

            self.backward_transport_header_length += (
                packet.transport_header_length
            )

            if self.last_backward_seen is not None:
                self.backward_iat.add(
                    packet.timestamp - self.last_backward_seen
                )

            self.last_backward_seen = packet.timestamp

            if (
                packet.protocol == "TCP"
                and self.init_win_bytes_backward is None
            ):
                self.init_win_bytes_backward = packet.tcp_window

        for flag in packet.tcp_flags:
            self.tcp_flags[flag] = self.tcp_flags.get(flag, 0) + 1
            direction_flags[flag] = direction_flags.get(flag, 0) + 1

        self.last_seen = packet.timestamp

    def to_record(self) -> dict:
        # A record represents a completed flow. Finalize activity
        # statistics exactly once before exporting the record.
        self.activity_tracker.finalize()
        activity = self.activity_tracker.snapshot()

        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "event_id": self.event_id,

            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,
            "bytes_sent": self.forward_bytes,
            "bytes_received": self.backward_bytes,
            "packets": self.total_packets,

            "forward_header_length": self.forward_header_length,
            "backward_header_length": self.backward_header_length,

            "forward_payload_bytes": self.forward_payload_bytes,
            "backward_payload_bytes": self.backward_payload_bytes,
            "forward_transport_header_length": (
                self.forward_transport_header_length
            ),
            "backward_transport_header_length": (
                self.backward_transport_header_length
            ),

            "duration": self.duration,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,

            "tcp_flags": dict(self.tcp_flags),
            "forward_tcp_flags": dict(self.forward_tcp_flags),
            "backward_tcp_flags": dict(self.backward_tcp_flags),

            "init_win_bytes_forward": self.init_win_bytes_forward,
            "init_win_bytes_backward": self.init_win_bytes_backward,

            "act_data_pkt_fwd": self.act_data_pkt_fwd,
            "min_seg_size_forward": self.min_seg_size_forward,

            "forward_lengths": self.forward_lengths.snapshot(),
            "backward_lengths": self.backward_lengths.snapshot(),
            "all_lengths": self.all_lengths.snapshot(),

            "forward_payload_lengths": (
                self.forward_payload_lengths.snapshot()
            ),
            "backward_payload_lengths": (
                self.backward_payload_lengths.snapshot()
            ),
            "all_payload_lengths": self.all_payload_lengths.snapshot(),

            "flow_iat": self.flow_iat.snapshot(),
            "forward_iat": self.forward_iat.snapshot(),
            "backward_iat": self.backward_iat.snapshot(),

            # Activity and subflow features.
            "subflow_count": activity["subflow_count"],
            "subflow_forward_packets": (
                activity["average_subflow_forward_packets"]
            ),
            "subflow_backward_packets": (
                activity["average_subflow_backward_packets"]
            ),
            "subflow_forward_bytes": (
                activity["average_subflow_forward_bytes"]
            ),
            "subflow_backward_bytes": (
                activity["average_subflow_backward_bytes"]
            ),
            "active": activity["active"],
            "idle": activity["idle"],
        }


class FlowAggregator:
    """Maintains active bidirectional flows with bounded capacity."""

    def __init__(
        self,
        idle_timeout: float = 30.0,
        max_active_flows: int = 10_000,
        flow_timeout: float = 120.0,
        activity_timeout: float = 5.0,
        subflow_timeout: float = 1.0,
    ):
        for name, value in (
            ("idle_timeout", idle_timeout),
            ("flow_timeout", flow_timeout),
            ("activity_timeout", activity_timeout),
            ("subflow_timeout", subflow_timeout),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive and finite")

        if (
            isinstance(max_active_flows, bool)
            or not isinstance(max_active_flows, int)
            or max_active_flows <= 0
        ):
            raise ValueError("Maximum active flows must be a positive integer")

        self.idle_timeout = idle_timeout
        self.flow_timeout = flow_timeout
        self.activity_timeout = activity_timeout
        self.subflow_timeout = subflow_timeout
        self.max_active_flows = max_active_flows

        self.active_flows: dict[FlowKey, FlowAccumulator] = {}
        self.rejected_new_flow_packets = 0

    def _create_flow(self, packet: PacketRecord) -> FlowAccumulator:
        return FlowAccumulator(
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
            activity_tracker=FlowActivityTracker(
                activity_timeout=self.activity_timeout,
                subflow_timeout=self.subflow_timeout,
            ),
        )

    def ingest(self, packet: PacketRecord) -> list[dict]:
        key = FlowKey.from_packet(packet)

        existing_flow = self.active_flows.get(key)

        if existing_flow is not None:
            if packet.timestamp < existing_flow.last_seen:
                raise ValueError("Out-of-order packet timestamp")

        expired = self.flush_expired(packet.timestamp)

        flow = self.active_flows.get(key)

        if (
            flow is not None
            and packet.timestamp - flow.first_seen > self.flow_timeout
        ):
            if flow.total_packets > 0:
                expired.append(flow.to_record())

            del self.active_flows[key]
            flow = None

        if flow is None:
            if len(self.active_flows) >= self.max_active_flows:
                self.rejected_new_flow_packets += 1
                raise FlowCapacityError(
                    "Active flow capacity reached; new flow rejected"
                )

            flow = self._create_flow(packet)
            self.active_flows[key] = flow

        flow.add_packet(packet)

        return expired

    def flush_expired(self, current_time: float) -> list[dict]:
        if (
            isinstance(current_time, bool)
            or not isinstance(current_time, (int, float))
            or not math.isfinite(current_time)
            or current_time < 0
        ):
            raise ValueError("Invalid current time")

        expired = []

        for key, flow in list(self.active_flows.items()):
            if current_time < flow.last_seen:
                continue

            if current_time - flow.last_seen >= self.idle_timeout:
                expired.append(flow.to_record())
                del self.active_flows[key]

        return expired

    def flush_all(self) -> list[dict]:
        records = [
            flow.to_record()
            for flow in self.active_flows.values()
        ]

        self.active_flows.clear()

        return records
