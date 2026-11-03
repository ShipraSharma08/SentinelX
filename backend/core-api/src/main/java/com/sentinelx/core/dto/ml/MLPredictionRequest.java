package com.sentinelx.core.dto.ml;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;

import java.util.Map;

public record MLPredictionRequest(
        @NotEmpty(message = "Feature map must not be empty")
        Map<String, Double> features,

        @Positive(message = "Network flow ID must be positive")
        Long networkFlowId
) {
}
