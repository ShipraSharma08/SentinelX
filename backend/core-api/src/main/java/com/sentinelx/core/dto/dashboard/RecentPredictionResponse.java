package com.sentinelx.core.dto.dashboard;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

public record RecentPredictionResponse(
        Long id,
        String prediction,
        String modelName,
        String modelVersion,
        BigDecimal confidence,
        BigDecimal riskScore,
        OffsetDateTime predictedAt
) {
}
