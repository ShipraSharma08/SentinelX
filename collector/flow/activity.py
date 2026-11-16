
from __future__ import annotations

import math
from dataclasses import dataclass, field

from collector.flow.statistics import StreamingStatistics


@dataclass
class FlowActivityTracker:
    """Constant-memory CICFlowMeter-style activity and subflow tracker."""

    activity_timeout: float = 5.0
    subflow_timeout: float = 1.0

    active_durations: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )
    idle_durations: StreamingStatistics = field(
        default_factory=StreamingStatistics
    )

    subflow_count: int = 0

    # Current subflow counters.
    subflow_forward_packets: int = 0
    subflow_backward_packets: int = 0
    subflow_forward_bytes: int = 0
    subflow_backward_bytes: int = 0

    # Accumulated counters from completed subflows.
    completed_forward_packets: int = 0
    completed_backward_packets: int = 0
    completed_forward_bytes: int = 0
    completed_backward_bytes: int = 0

    start_time: float | None = None
    last_packet_time: float | None = None
    active_start_time: float | None = None
    active_end_time: float | None = None
    subflow_last_packet_time: float | None = None

    finalized: bool = False

    def __post_init__(self) -> None:
        for name, value in (
            ("activity_timeout", self.activity_timeout),
            ("subflow_timeout", self.subflow_timeout),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive and finite")

    def _finish_subflow(self) -> None:
        self.completed_forward_packets += self.subflow_forward_packets
        self.completed_backward_packets += self.subflow_backward_packets
        self.completed_forward_bytes += self.subflow_forward_bytes
        self.completed_backward_bytes += self.subflow_backward_bytes

        self.subflow_forward_packets = 0
        self.subflow_backward_packets = 0
        self.subflow_forward_bytes = 0
        self.subflow_backward_bytes = 0

    def add_packet(
        self,
        timestamp: float,
        is_forward: bool,
        packet_length: int,
    ) -> None:
        if self.finalized:
            raise RuntimeError("Cannot add packets to a finalized tracker")

        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
            or timestamp < 0
        ):
            raise ValueError("Invalid packet timestamp")

        if (
            isinstance(packet_length, bool)
            or not isinstance(packet_length, int)
            or packet_length < 0
        ):
            raise ValueError("Packet length must be a non-negative integer")

        if not isinstance(is_forward, bool):
            raise ValueError("is_forward must be a boolean")

        if (
            self.last_packet_time is not None
            and timestamp < self.last_packet_time
        ):
            raise ValueError("Out-of-order packet timestamp")

        if self.start_time is None:
            self.start_time = timestamp
            self.active_start_time = timestamp
            self.active_end_time = timestamp
            self.subflow_last_packet_time = timestamp
            self.subflow_count = 1

        else:
            assert self.active_end_time is not None
            assert self.active_start_time is not None
            assert self.subflow_last_packet_time is not None

            gap = timestamp - self.active_end_time

            if gap > self.activity_timeout:
                active_duration = (
                    self.active_end_time - self.active_start_time
                )

                if active_duration > 0:
                    self.active_durations.add(active_duration)

                self.idle_durations.add(gap)

                self.active_start_time = timestamp
                self.active_end_time = timestamp
            else:
                self.active_end_time = timestamp

            subflow_gap = timestamp - self.subflow_last_packet_time

            if subflow_gap > self.subflow_timeout:
                self._finish_subflow()
                self.subflow_count += 1

            self.subflow_last_packet_time = timestamp

        if is_forward:
            self.subflow_forward_packets += 1
            self.subflow_forward_bytes += packet_length
        else:
            self.subflow_backward_packets += 1
            self.subflow_backward_bytes += packet_length

        self.last_packet_time = timestamp

    def finalize(self) -> None:
        """Close the current active period and subflow exactly once."""

        if self.finalized:
            return

        if self.start_time is not None:
            assert self.active_start_time is not None
            assert self.active_end_time is not None

            active_duration = (
                self.active_end_time - self.active_start_time
            )

            if active_duration > 0:
                self.active_durations.add(active_duration)

            self._finish_subflow()

        self.finalized = True

    def snapshot(self) -> dict:
        total_forward_packets = (
            self.completed_forward_packets + self.subflow_forward_packets
        )
        total_backward_packets = (
            self.completed_backward_packets + self.subflow_backward_packets
        )
        total_forward_bytes = (
            self.completed_forward_bytes + self.subflow_forward_bytes
        )
        total_backward_bytes = (
            self.completed_backward_bytes + self.subflow_backward_bytes
        )

        count = self.subflow_count

        return {
            "subflow_count": count,

            # Current subflow counters retained for compatibility.
            "subflow_forward_packets": self.subflow_forward_packets,
            "subflow_backward_packets": self.subflow_backward_packets,
            "subflow_forward_bytes": self.subflow_forward_bytes,
            "subflow_backward_bytes": self.subflow_backward_bytes,

            # Average counters across all subflows.
            "average_subflow_forward_packets": (
                total_forward_packets / count if count else 0.0
            ),
            "average_subflow_backward_packets": (
                total_backward_packets / count if count else 0.0
            ),
            "average_subflow_forward_bytes": (
                total_forward_bytes / count if count else 0.0
            ),
            "average_subflow_backward_bytes": (
                total_backward_bytes / count if count else 0.0
            ),

            "active": self.active_durations.snapshot(),
            "idle": self.idle_durations.snapshot(),
            "active_start_time": self.active_start_time,
            "active_end_time": self.active_end_time,
            "finalized": self.finalized,
        }
