package com.sentinelx.core.controller;

import com.sentinelx.core.dto.dashboard.DashboardOverviewResponse;
import com.sentinelx.core.dto.dashboard.RecentAlertResponse;
import com.sentinelx.core.dto.dashboard.RecentNetworkFlowResponse;
import com.sentinelx.core.dto.dashboard.RecentPredictionResponse;
import com.sentinelx.core.service.DashboardService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    public DashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    @GetMapping("/overview")
    public ResponseEntity<DashboardOverviewResponse> getOverview() {
        return ResponseEntity.ok(dashboardService.getOverview());
    }

    @GetMapping("/recent-alerts")
    public ResponseEntity<List<RecentAlertResponse>> getRecentAlerts() {
        return ResponseEntity.ok(dashboardService.getRecentAlerts());
    }

    @GetMapping("/recent-predictions")
    public ResponseEntity<List<RecentPredictionResponse>> getRecentPredictions() {
        return ResponseEntity.ok(dashboardService.getRecentPredictions());
    }

    @GetMapping("/recent-flows")
    public ResponseEntity<List<RecentNetworkFlowResponse>> getRecentNetworkFlows() {
        return ResponseEntity.ok(dashboardService.getRecentNetworkFlows());
    }
}
