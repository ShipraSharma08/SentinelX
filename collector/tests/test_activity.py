
import pytest

from collector.flow.activity import FlowActivityTracker


def test_initial_packet_starts_first_subflow():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)

    result = tracker.snapshot()

    assert result["subflow_count"] == 1
    assert result["subflow_forward_packets"] == 1
    assert result["subflow_forward_bytes"] == 100


def test_packets_within_one_second_remain_in_same_subflow():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(2.0, False, 200)

    result = tracker.snapshot()

    assert result["subflow_count"] == 1
    assert result["subflow_forward_packets"] == 1
    assert result["subflow_backward_packets"] == 1


def test_gap_greater_than_one_second_starts_new_subflow():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(2.1, False, 200)

    result = tracker.snapshot()

    assert result["subflow_count"] == 2
    assert result["subflow_forward_packets"] == 0
    assert result["subflow_backward_packets"] == 1
    assert result["subflow_backward_bytes"] == 200


def test_activity_gap_greater_than_five_seconds_records_idle_time():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(2.0, True, 100)
    tracker.add_packet(8.0, False, 200)

    result = tracker.snapshot()

    assert result["active_start_time"] == 8.0
    assert result["active_end_time"] == 8.0
    assert result["active"]["count"] == 1
    assert result["active"]["mean"] == pytest.approx(1.0)
    assert result["idle"]["count"] == 1
    assert result["idle"]["mean"] == pytest.approx(6.0)


def test_exact_activity_timeout_does_not_start_new_active_period():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(6.0, True, 100)

    result = tracker.snapshot()

    assert result["active"]["count"] == 0
    assert result["idle"]["count"] == 0


def test_out_of_order_timestamp_is_rejected():
    tracker = FlowActivityTracker()

    tracker.add_packet(2.0, True, 100)

    with pytest.raises(ValueError, match="Out-of-order"):
        tracker.add_packet(1.0, True, 100)


def test_negative_packet_length_is_rejected():
    tracker = FlowActivityTracker()

    with pytest.raises(ValueError):
        tracker.add_packet(1.0, True, -1)


def test_invalid_timeout_is_rejected():
    with pytest.raises(ValueError):
        FlowActivityTracker(activity_timeout=0)

    with pytest.raises(ValueError):
        FlowActivityTracker(subflow_timeout=-1)


def test_tracker_does_not_store_packet_history():
    tracker = FlowActivityTracker()

    for timestamp in range(1, 1001):
        tracker.add_packet(float(timestamp), True, 100)

    assert not hasattr(tracker, "packets")
    assert not hasattr(tracker, "packet_history")
