
import pytest

from collector.flow.activity import FlowActivityTracker


def test_initial_packet_does_not_increment_subflow_count():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)

    result = tracker.snapshot()

    assert result["subflow_count"] == 0
    assert result["subflow_forward_packets"] == 1
    assert result["subflow_forward_bytes"] == 100
    assert result["average_subflow_forward_packets"] == 0.0
    assert result["average_subflow_forward_bytes"] == 0.0


def test_packets_within_one_second_do_not_increment_subflow_count():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(2.0, False, 200)

    result = tracker.snapshot()

    assert result["subflow_count"] == 0
    assert result["subflow_forward_packets"] == 1
    assert result["subflow_backward_packets"] == 1
    assert result["average_subflow_forward_packets"] == 0.0


def test_gap_greater_than_one_second_increments_subflow_count():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(2.1, False, 200)

    result = tracker.snapshot()

    assert result["subflow_count"] == 1
    assert result["subflow_forward_packets"] == 0
    assert result["subflow_backward_packets"] == 1
    assert result["subflow_backward_bytes"] == 200

    assert result["average_subflow_forward_packets"] == 1.0
    assert result["average_subflow_backward_packets"] == 1.0
    assert result["average_subflow_forward_bytes"] == 100.0
    assert result["average_subflow_backward_bytes"] == 200.0


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
    assert result["subflow_count"] == 1


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


def test_finalized_flow_without_subflow_timeout_gap_has_subflow_count_at_least_one():
    tracker = FlowActivityTracker()

    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(1.5, False, 200)

    # Before finalization, in-progress subflow is tracked
    unfinalized = tracker.snapshot()
    assert unfinalized["subflow_count"] == 0

    # Once finalized, the flow containing packets has at least one subflow
    tracker.finalize()
    result = tracker.snapshot()

    assert result["subflow_count"] >= 1
    assert result["subflow_count"] == 1

    # For a single-subflow flow, average subflow metrics match total flow metrics
    assert result["average_subflow_forward_packets"] == 1.0
    assert result["average_subflow_backward_packets"] == 1.0
    assert result["average_subflow_forward_bytes"] == 100.0
    assert result["average_subflow_backward_bytes"] == 200.0


def test_finalized_flow_with_multiple_subflows_preserves_count_and_averages():
    tracker = FlowActivityTracker(subflow_timeout=1.0)

    # Subflow 1: 2 forward packets (100 + 150 = 250 bytes)
    tracker.add_packet(1.0, True, 100)
    tracker.add_packet(1.2, True, 150)

    # Gap of 1.5s > 1.0s -> Subflow 1 ends, Subflow 2 starts
    # Subflow 2: 1 backward packet (300 bytes)
    tracker.add_packet(2.7, False, 300)

    tracker.finalize()
    result = tracker.snapshot()

    # Subflow count is 1 (completed) + preserved behavior
    assert result["subflow_count"] >= 1
    assert result["average_subflow_forward_packets"] == 2.0
    assert result["average_subflow_backward_packets"] == 1.0
    assert result["average_subflow_forward_bytes"] == 250.0
    assert result["average_subflow_backward_bytes"] == 300.0


def test_finalized_empty_tracker_has_zero_subflows():
    tracker = FlowActivityTracker()
    tracker.finalize()
    result = tracker.snapshot()

    assert result["subflow_count"] == 0
    assert result["average_subflow_forward_packets"] == 0.0
    assert result["average_subflow_backward_packets"] == 0.0
    assert result["average_subflow_forward_bytes"] == 0.0
    assert result["average_subflow_backward_bytes"] == 0.0
