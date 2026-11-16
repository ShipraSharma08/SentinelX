
package com.sentinelx.core.dto.collector;

import java.time.OffsetDateTime;

public record CollectorFlowResponse(
        Long flowId,
        Long predictionId,
        Long sourceAssetId,
        Long destinationAssetId,
        String prediction,
        Double attackProbability,
        String model,
        OffsetDateTime timestamp,
        String status
) {
}
