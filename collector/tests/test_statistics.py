import math

import pytest

from collector.flow.statistics import StreamingStatistics


def test_streaming_statistics_calculates_mean_and_variance():
    stats = StreamingStatistics()

    for value in [10, 20, 30, 40]:
        stats.add(value)

    result = stats.snapshot()

    assert result["count"] == 4
    assert result["min"] == 10
    assert result["max"] == 40
    assert result["mean"] == 25
    assert result["variance"] == 125
    assert result["std"] == pytest.approx(math.sqrt(125))


def test_single_value_has_zero_variance():
    stats = StreamingStatistics()
    stats.add(42)

    assert stats.mean == 42
    assert stats.variance == 0
    assert stats.standard_deviation == 0


def test_empty_statistics_are_safe():
    stats = StreamingStatistics()
    result = stats.snapshot()

    assert result["count"] == 0
    assert result["min"] is None
    assert result["max"] is None
    assert result["mean"] is None
    assert result["variance"] == 0
    assert result["std"] == 0


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_non_finite_values_are_rejected(value):
    stats = StreamingStatistics()

    with pytest.raises(ValueError):
        stats.add(value)


def test_statistics_do_not_retain_individual_samples():
    stats = StreamingStatistics()

    for value in range(10000):
        stats.add(value)

    assert stats.count == 10000
    assert not hasattr(stats, "values")
    assert not hasattr(stats, "samples")


def test_sample_variance_matches_apache_commons_math():
    stats = StreamingStatistics()

    for value in [10, 20, 30, 40]:
        stats.add(value)

    assert stats.sample_variance == pytest.approx(500 / 3)


def test_sample_standard_deviation_matches_apache_commons_math():
    stats = StreamingStatistics()

    for value in [10, 20, 30, 40]:
        stats.add(value)

    assert stats.sample_standard_deviation == pytest.approx(
        math.sqrt(500 / 3)
    )


def test_sample_statistics_for_single_value_are_zero():
    stats = StreamingStatistics()
    stats.add(42)

    assert stats.sample_variance == 0
    assert stats.sample_standard_deviation == 0


def test_sample_statistics_are_zero_when_empty():
    stats = StreamingStatistics()

    assert stats.sample_variance == 0
    assert stats.sample_standard_deviation == 0
