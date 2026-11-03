
package com.sentinelx.core.dto.ml;

public record MLPredictionResponse(
        String prediction,
        Double attack_probability,
        String model
) {
}
