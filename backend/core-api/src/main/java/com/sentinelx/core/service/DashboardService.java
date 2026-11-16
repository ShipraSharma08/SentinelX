package com.sentinelx.core.service;

import com.sentinelx.core.dto.dashboard.DashboardOverviewResponse;
import com.sentinelx.core.dto.dashboard.RecentAlertResponse;
import com.sentinelx.core.dto.dashboard.RecentNetworkFlowResponse;
import com.sentinelx.core.dto.dashboard.RecentPredictionResponse;
import com.sentinelx.core.repository.AlertRepository;
import com.sentinelx.core.repository.AssetRepository;
import com.sentinelx.core.repository.IncidentRepository;
import com.sentinelx.core.repository.MLPredictionRepository;
import com.sentinelx.core.repository.NetworkFlowRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = true)
public class DashboardService {

    private final AssetRepository assetRepository;
    private final NetworkFlowRepository networkFlowRepository;
    private final MLPredictionRepository mlPredictionRepository;
    private final AlertRepository alertRepository;
    private final IncidentRepository incidentRepository;

    public DashboardService(
            AssetRepository assetRepository,
            NetworkFlowRepository networkFlowRepository,
            MLPredictionRepository mlPredictionRepository,
            AlertRepository alertRepository,
            IncidentRepository incidentRepository
    ) {
        this.assetRepository = assetRepository;
        this.networkFlowRepository = networkFlowRepository;
        this.mlPredictionRepository = mlPredictionRepository;
        this.alertRepository = alertRepository;
        this.incidentRepository = incidentRepository;
    }

    public DashboardOverviewResponse getOverview() {

        long totalPredictions = mlPredictionRepository.count();
        long benignPredictions =
                mlPredictionRepository.countByPredictionIgnoreCase("BENIGN");

        return new DashboardOverviewResponse(
                assetRepository.count(),
                networkFlowRepository.count(),
                totalPredictions,
                alertRepository.count(),
                alertRepository.countByStatusIgnoreCase("OPEN"),
                alertRepository.countBySeverityIgnoreCase("CRITICAL"),
                incidentRepository.count(),
                incidentRepository.countActiveIncidents(),
                Math.max(0, totalPredictions - benignPredictions)
        );
    }

    public List<RecentAlertResponse> getRecentAlerts() {
        return alertRepository.findTop10ByOrderByCreatedAtDesc()
                .stream()
                .map(alert -> new RecentAlertResponse(
                        alert.getId(),
                        alert.getTitle(),
                        alert.getDescription(),
                        alert.getSeverity(),
                        alert.getRiskScore(),
                        alert.getStatus(),
                        alert.getMlPredictionId(),
                        alert.getCreatedAt()
                ))
                .toList();
    }

    public List<RecentPredictionResponse> getRecentPredictions() {
        return mlPredictionRepository.findTop10ByOrderByPredictedAtDesc()
                .stream()
                .map(prediction -> new RecentPredictionResponse(
                        prediction.getId(),
                        prediction.getPrediction(),
                        prediction.getModelName(),
                        prediction.getModelVersion(),
                        prediction.getConfidence(),
                        prediction.getRiskScore(),
                        prediction.getPredictedAt()
                ))
                .toList();
    }

    public List<RecentNetworkFlowResponse> getRecentNetworkFlows() {
        return networkFlowRepository.findTop10ByOrderByTimestampDesc()
                .stream()
                .map(flow -> new RecentNetworkFlowResponse(
                        flow.getId(),
                        flow.getSourceAsset().getIpAddress(),
                        flow.getDestinationAsset().getIpAddress(),
                        flow.getSourcePort(),
                        flow.getDestinationPort(),
                        flow.getProtocol(),
                        flow.getBytesSent(),
                        flow.getBytesReceived(),
                        flow.getPackets(),
                        flow.getDuration(),
                        flow.getTimestamp()
                ))
                .toList();
    }
}
