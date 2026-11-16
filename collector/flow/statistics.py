
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class StreamingStatistics:
    """Calculate numeric statistics using constant memory."""

    count: int = 0
    minimum: float | None = None
    maximum: float | None = None
    mean: float = 0.0
    _m2: float = 0.0

    def add(self, value: float) -> None:
        value = float(value)

        if not math.isfinite(value):
            raise ValueError("Statistic value must be finite")

        self.count += 1

        if self.minimum is None or value < self.minimum:
            self.minimum = value

        if self.maximum is None or value > self.maximum:
            self.maximum = value

        delta = value - self.mean
        self.mean += delta / self.count
        delta_after_mean = value - self.mean
        self._m2 += delta * delta_after_mean

    @property
    def variance(self) -> float:
        """Population variance."""
        if self.count == 0:
            return 0.0

        return max(0.0, self._m2 / self.count)

    @property
    def standard_deviation(self) -> float:
        """Population standard deviation."""
        return math.sqrt(self.variance)

    @property
    def sample_variance(self) -> float:
        """Sample variance, matching Apache Commons Math."""
        if self.count < 2:
            return 0.0

        return max(0.0, self._m2 / (self.count - 1))

    @property
    def sample_standard_deviation(self) -> float:
        """Sample standard deviation, matching Apache Commons Math."""
        return math.sqrt(self.sample_variance)

    def snapshot(self) -> dict:
        return {
            "count": self.count,
            "min": self.minimum,
            "max": self.maximum,
            "mean": self.mean if self.count else None,
            "variance": self.variance,
            "std": self.standard_deviation,
            "sample_variance": self.sample_variance,
            "sample_std": self.sample_standard_deviation,
        }
