package com.sentinelx.core.dto.dashboard;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

public record RecentAlertResponse(
        Long id,
        String title,
        String description,
        String severity,
        BigDecimal riskScore,
        String status,
        Long mlPredictionId,
        OffsetDateTime createdAt
) {
}
