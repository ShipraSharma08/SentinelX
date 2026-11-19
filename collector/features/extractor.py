
from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


FEATURE_NAMES = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)


def _number(value: Any, field: str) -> float:
    """Convert a required value to a finite float."""
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric, not boolean")

    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc

    if not math.isfinite(result):
        raise ValueError(f"{field} must be finite")

    return result


def _value(flow: Mapping[str, Any], key: str) -> float:
    if key not in flow:
        raise ValueError(
            f"Flow record is missing required field: {key}"
        )

    return _number(flow[key], key)


def _stat(
    flow: Mapping[str, Any],
    group: str,
    metric: str,
    *,
    scale: float = 1.0,
) -> float:
    """Read a statistic snapshot; empty statistics map to zero."""
    snapshot = flow.get(group)

    if not isinstance(snapshot, Mapping):
        raise ValueError(
            f"Flow record has invalid statistics: {group}"
        )

    count = snapshot.get("count")

    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
    ):
        raise ValueError(
            f"{group}.count must be a non-negative integer"
        )

    if count == 0:
        return 0.0

    if metric not in snapshot:
        raise ValueError(
            f"{group} is missing statistic: {metric}"
        )

    return (
        _number(snapshot[metric], f"{group}.{metric}")
        * scale
    )


def _flag(flow: Mapping[str, Any], name: str) -> float:
    flags = flow.get("tcp_flags")

    if not isinstance(flags, Mapping):
        raise ValueError("Flow record has invalid tcp_flags")

    count = _number(
        flags.get(name, 0),
        f"tcp_flags.{name}",
    )
    return 1.0 if count > 0 else 0.0


def _activity_stat(
    flow: Mapping[str, Any],
    group: str,
    metric: str,
) -> float:
    """Convert activity durations from seconds to microseconds."""
    return _stat(
        flow,
        group,
        metric,
        scale=1_000_000.0,
    )


def _directional_flag(
    flow: Mapping[str, Any],
    direction: str,
    name: str,
) -> float:
    key = f"{direction}_tcp_flags"
    flags = flow.get(key)

    if not isinstance(flags, Mapping):
        raise ValueError(f"Flow record has invalid {key}")

    count = _number(
        flags.get(name, 0),
        f"{key}.{name}",
    )
    return 1.0 if count > 0 else 0.0


def extract_features(
    flow: Mapping[str, Any],
) -> dict[str, float]:
    """
    Convert one completed flow record into the model's
    exact 70-feature input contract.

    Timestamp-derived durations and IAT values are converted
    from seconds to microseconds.

    Packet-length features use payload lengths.
    Standard deviations use sample standard deviation.
    """
    if not isinstance(flow, Mapping):
        raise TypeError("flow must be a mapping")

    forward_packets = _value(flow, "forward_packets")
    backward_packets = _value(flow, "backward_packets")
    total_packets = _value(flow, "packets")

    forward_bytes = _value(
        flow,
        "forward_payload_bytes",
    )
    backward_bytes = _value(
        flow,
        "backward_payload_bytes",
    )

    duration_seconds = _value(flow, "duration")

    if duration_seconds < 0:
        raise ValueError("Flow duration cannot be negative")

    duration_microseconds = (
        duration_seconds * 1_000_000.0
    )

    duration_for_rate = (
        duration_seconds
        if duration_seconds > 0
        else 0.0
    )

    flow_bytes_per_second = (
        (forward_bytes + backward_bytes) / duration_for_rate
        if duration_for_rate > 0
        else 0.0
    )

    flow_packets_per_second = (
        total_packets / duration_for_rate
        if duration_for_rate > 0
        else 0.0
    )

    forward_packets_per_second = (
        forward_packets / duration_for_rate
        if duration_for_rate > 0
        else 0.0
    )

    backward_packets_per_second = (
        backward_packets / duration_for_rate
        if duration_for_rate > 0
        else 0.0
    )

    # IAT totals = mean * number of IAT observations.
    flow_iat_total = (
        _stat(flow, "flow_iat", "mean")
        * _number(
            flow["flow_iat"]["count"],
            "flow_iat.count",
        )
        * 1_000_000.0
    )

    forward_iat_total = (
        _stat(flow, "forward_iat", "mean")
        * _number(
            flow["forward_iat"]["count"],
            "forward_iat.count",
        )
        * 1_000_000.0
    )

    backward_iat_total = (
        _stat(flow, "backward_iat", "mean")
        * _number(
            flow["backward_iat"]["count"],
            "backward_iat.count",
        )
        * 1_000_000.0
    )

    features = {
        "Destination Port": _value(
            flow, "destination_port"
        ),
        "Flow Duration": duration_microseconds,

        "Total Fwd Packets": forward_packets,
        "Total Backward Packets": backward_packets,

        "Total Length of Fwd Packets": forward_bytes,
        "Total Length of Bwd Packets": backward_bytes,

        "Fwd Packet Length Max": _stat(
            flow, "forward_payload_lengths", "max"
        ),
        "Fwd Packet Length Min": _stat(
            flow, "forward_payload_lengths", "min"
        ),
        "Fwd Packet Length Mean": _stat(
            flow, "forward_payload_lengths", "mean"
        ),
        "Fwd Packet Length Std": _stat(
            flow, "forward_payload_lengths", "sample_std"
        ),

        "Bwd Packet Length Max": _stat(
            flow, "backward_payload_lengths", "max"
        ),
        "Bwd Packet Length Min": _stat(
            flow, "backward_payload_lengths", "min"
        ),
        "Bwd Packet Length Mean": _stat(
            flow, "backward_payload_lengths", "mean"
        ),
        "Bwd Packet Length Std": _stat(
            flow, "backward_payload_lengths", "sample_std"
        ),

        "Flow Bytes/s": flow_bytes_per_second,
        "Flow Packets/s": flow_packets_per_second,

        "Flow IAT Mean": _stat(
            flow, "flow_iat", "mean",
            scale=1_000_000.0,
        ),
        "Flow IAT Std": _stat(
            flow, "flow_iat", "sample_std",
            scale=1_000_000.0,
        ),
        "Flow IAT Max": _stat(
            flow, "flow_iat", "max",
            scale=1_000_000.0,
        ),
        "Flow IAT Min": _stat(
            flow, "flow_iat", "min",
            scale=1_000_000.0,
        ),

        "Fwd IAT Total": forward_iat_total,
        "Fwd IAT Mean": _stat(
            flow, "forward_iat", "mean",
            scale=1_000_000.0,
        ),
        "Fwd IAT Std": _stat(
            flow, "forward_iat", "sample_std",
            scale=1_000_000.0,
        ),
        "Fwd IAT Max": _stat(
            flow, "forward_iat", "max",
            scale=1_000_000.0,
        ),
        "Fwd IAT Min": _stat(
            flow, "forward_iat", "min",
            scale=1_000_000.0,
        ),

        "Bwd IAT Total": backward_iat_total,
        "Bwd IAT Mean": _stat(
            flow, "backward_iat", "mean",
            scale=1_000_000.0,
        ),
        "Bwd IAT Std": _stat(
            flow, "backward_iat", "sample_std",
            scale=1_000_000.0,
        ),
        "Bwd IAT Max": _stat(
            flow, "backward_iat", "max",
            scale=1_000_000.0,
        ),
        "Bwd IAT Min": _stat(
            flow, "backward_iat", "min",
            scale=1_000_000.0,
        ),

        "Fwd PSH Flags": _directional_flag(
            flow, "forward", "PSH"
        ),
        "Fwd URG Flags": _directional_flag(
            flow, "forward", "URG"
        ),

        "Fwd Header Length": _value(
            flow, "forward_transport_header_length"
        ),
        "Bwd Header Length": _value(
            flow, "backward_transport_header_length"
        ),

        "Fwd Packets/s": forward_packets_per_second,
        "Bwd Packets/s": backward_packets_per_second,

        "Min Packet Length": _stat(
            flow, "all_payload_lengths", "min"
        ),
        "Max Packet Length": _stat(
            flow, "all_payload_lengths", "max"
        ),
        "Packet Length Mean": _stat(
            flow, "all_payload_lengths", "mean"
        ),
        "Packet Length Std": _stat(
            flow, "all_payload_lengths", "sample_std"
        ),
        "Packet Length Variance": _stat(
            flow, "all_payload_lengths", "sample_variance"
        ),

        "FIN Flag Count": _flag(flow, "FIN"),
        "SYN Flag Count": _flag(flow, "SYN"),
        "RST Flag Count": _flag(flow, "RST"),
        "PSH Flag Count": _flag(flow, "PSH"),
        "ACK Flag Count": _flag(flow, "ACK"),
        "URG Flag Count": _flag(flow, "URG"),
        "CWE Flag Count": _flag(flow, "CWE"),
        "ECE Flag Count": _flag(flow, "ECE"),

        "Down/Up Ratio": (
            backward_packets / forward_packets
            if forward_packets > 0
            else 0.0
        ),

        "Average Packet Size": (
            (forward_bytes + backward_bytes) / total_packets
            if total_packets > 0
            else 0.0
        ),

        "Avg Fwd Segment Size": (
            forward_bytes / forward_packets
            if forward_packets > 0
            else 0.0
        ),

        "Avg Bwd Segment Size": (
            backward_bytes / backward_packets
            if backward_packets > 0
            else 0.0
        ),

        "Fwd Header Length.1": _value(
            flow, "forward_transport_header_length"
        ),

        "Subflow Fwd Packets": _value(
            flow, "subflow_forward_packets"
        ),
        "Subflow Fwd Bytes": _value(
            flow, "subflow_forward_bytes"
        ),
        "Subflow Bwd Packets": _value(
            flow, "subflow_backward_packets"
        ),
        "Subflow Bwd Bytes": _value(
            flow, "subflow_backward_bytes"
        ),

        "Init_Win_bytes_forward": (
            -1.0
            if flow.get("init_win_bytes_forward") is None
            else _value(flow, "init_win_bytes_forward")
        ),

        "Init_Win_bytes_backward": (
            -1.0
            if flow.get("init_win_bytes_backward") is None
            else _value(flow, "init_win_bytes_backward")
        ),

        "act_data_pkt_fwd": _value(
            flow, "act_data_pkt_fwd"
        ),

        "min_seg_size_forward": _value(
            flow, "min_seg_size_forward"
        ),

        "Active Mean": _activity_stat(
            flow, "active", "mean"
        ),
        "Active Std": _activity_stat(
            flow, "active", "sample_std"
        ),
        "Active Max": _activity_stat(
            flow, "active", "max"
        ),
        "Active Min": _activity_stat(
            flow, "active", "min"
        ),

        "Idle Mean": _activity_stat(
            flow, "idle", "mean"
        ),
        "Idle Std": _activity_stat(
            flow, "idle", "sample_std"
        ),
        "Idle Max": _activity_stat(
            flow, "idle", "max"
        ),
        "Idle Min": _activity_stat(
            flow, "idle", "min"
        ),
    }

    if tuple(features.keys()) != FEATURE_NAMES:
        raise RuntimeError(
            "Extractor feature order does not match model contract"
        )

    if len(features) != 70:
        raise RuntimeError(
            f"Expected 70 features, generated {len(features)}"
        )

    for name, value in features.items():
        if not math.isfinite(value):
            raise ValueError(
                f"Extracted feature is not finite: {name}"
            )

    return features
