package com.sentinelx.core.dto.dashboard;

public record DashboardOverviewResponse(
        long totalAssets,
        long totalNetworkFlows,
        long totalPredictions,
        long totalAlerts,
        long openAlerts,
        long criticalAlerts,
        long totalIncidents,
        long activeIncidents,
        long maliciousPredictions
) {
}
