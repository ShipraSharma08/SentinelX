
package com.sentinelx.core.service;

import com.sentinelx.core.dto.collector.CollectorFlowRequest;
import com.sentinelx.core.dto.collector.CollectorFlowResponse;
import com.sentinelx.core.model.Alert;
import com.sentinelx.core.model.Asset;
import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.model.NetworkFlow;
import com.sentinelx.core.model.SecurityEvent;
import com.sentinelx.core.repository.AlertRepository;
import com.sentinelx.core.repository.AssetRepository;
import com.sentinelx.core.repository.MLPredictionRepository;
import com.sentinelx.core.repository.NetworkFlowRepository;
import com.sentinelx.core.repository.SecurityEventRepository;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

@Service
public class CollectorIngestionService {

    private final AssetRepository assetRepository;
    private final NetworkFlowRepository networkFlowRepository;
    private final MLPredictionRepository mlPredictionRepository;
    private final SecurityEventRepository securityEventRepository;
    private final AlertRepository alertRepository;

    public CollectorIngestionService(
            AssetRepository assetRepository,
            NetworkFlowRepository networkFlowRepository,
            MLPredictionRepository mlPredictionRepository,
            SecurityEventRepository securityEventRepository,
            AlertRepository alertRepository) {

        this.assetRepository = assetRepository;
        this.networkFlowRepository = networkFlowRepository;
        this.mlPredictionRepository = mlPredictionRepository;
        this.securityEventRepository = securityEventRepository;
        this.alertRepository = alertRepository;
    }

    @Transactional
    public CollectorFlowResponse ingest(CollectorFlowRequest request) {

        validateRequest(request);

        networkFlowRepository.acquireEventLock(request.eventId());

        String sourceIp = normalizeIp(request.sourceIp());
        String destinationIp = normalizeIp(request.destinationIp());

        OffsetDateTime flowTimestamp = OffsetDateTime.ofInstant(
                Instant.ofEpochMilli(
                        Math.round(request.firstSeen() * 1000.0)
                ),
                ZoneOffset.UTC
        );

        String predictionLabel =
                request.prediction().toUpperCase(Locale.ROOT);

        double attackProbability = request.attackProbability();

        var existingFlow = networkFlowRepository.findByEventId(
                request.eventId()
        );

        if (existingFlow.isPresent()) {

            NetworkFlow flow = existingFlow.get();

            var existingPrediction =
                    mlPredictionRepository.findByNetworkFlow_Id(
                            flow.getId()
                    );

            if (existingPrediction.isEmpty()) {
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "Existing event has no associated prediction"
                );
            }

            MLPrediction prediction = existingPrediction.get();

            if (!matchesExistingEvent(
                    flow,
                    prediction,
                    request,
                    sourceIp,
                    destinationIp,
                    flowTimestamp,
                    predictionLabel,
                    attackProbability
            )) {
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "Event ID already exists with different data"
                );
            }

            return buildResponse(flow, prediction);
        }

        Asset sourceAsset = resolveAsset(sourceIp);
        Asset destinationAsset = resolveAsset(destinationIp);

        NetworkFlow flow = new NetworkFlow();

        flow.setEventId(request.eventId());
        flow.setSourceAsset(sourceAsset);
        flow.setDestinationAsset(destinationAsset);
        flow.setSourcePort(request.sourcePort());
        flow.setDestinationPort(request.destinationPort());
        flow.setProtocol(request.protocol().toUpperCase(Locale.ROOT));
        flow.setBytesSent(request.bytesSent());
        flow.setBytesReceived(request.bytesReceived());
        flow.setPackets(request.packets());
        flow.setDuration(request.duration());
        flow.setTimestamp(flowTimestamp);

        NetworkFlow savedFlow = networkFlowRepository.saveAndFlush(flow);

        double confidence = predictionLabel.equals("ATTACK")
                ? attackProbability
                : 1.0 - attackProbability;

        MLPrediction prediction = new MLPrediction();

        prediction.setNetworkFlow(savedFlow);
        prediction.setModelName(request.model().trim());
        prediction.setModelVersion("1.0");
        prediction.setPrediction(predictionLabel);

        prediction.setConfidence(
                BigDecimal.valueOf(confidence)
                        .setScale(6, RoundingMode.HALF_UP)
        );

        prediction.setRiskScore(
                BigDecimal.valueOf(attackProbability * 100.0)
                        .setScale(6, RoundingMode.HALF_UP)
        );

        prediction.setPredictedAt(OffsetDateTime.now(ZoneOffset.UTC));

        MLPrediction savedPrediction =
                mlPredictionRepository.saveAndFlush(prediction);

        if ("ATTACK".equals(predictionLabel)) {
            createSecurityEventAndAlert(
                    savedFlow,
                    savedPrediction,
                    sourceIp,
                    destinationIp
            );
        }

        return buildResponse(savedFlow, savedPrediction);
    }

    private void createSecurityEventAndAlert(
            NetworkFlow flow,
            MLPrediction prediction,
            String sourceIp,
            String destinationIp) {

        Long predictionId = prediction.getId();

        if (alertRepository.existsByMlPredictionId(predictionId)) {
            return;
        }

        BigDecimal riskScore = prediction.getRiskScore()
                .setScale(2, RoundingMode.HALF_UP);

        String severity = determineSeverity(riskScore);

        String description = String.format(
                Locale.ROOT,
                "ML model %s detected suspicious network activity. "
                        + "Source: %s:%d, Destination: %s:%d, "
                        + "Protocol: %s, Risk score: %s/100.",
                prediction.getModelName(),
                sourceIp,
                flow.getSourcePort(),
                destinationIp,
                flow.getDestinationPort(),
                flow.getProtocol(),
                riskScore.toPlainString()
        );

        SecurityEvent event = new SecurityEvent();

        event.setEventType("ML_ATTACK_DETECTION");
        event.setSeverity(severity);
        event.setSourceAsset(flow.getSourceAsset());
        event.setDestinationAsset(flow.getDestinationAsset());
        event.setSourceIp(sourceIp);
        event.setDestinationIp(destinationIp);
        event.setSourcePort(flow.getSourcePort());
        event.setDestinationPort(flow.getDestinationPort());
        event.setProtocol(flow.getProtocol());
        event.setDescription(description);
        event.setDetectedAt(prediction.getPredictedAt());

        SecurityEvent savedEvent =
                securityEventRepository.saveAndFlush(event);

        Alert alert = new Alert();

        alert.setSecurityEvent(savedEvent);
        alert.setMlPredictionId(predictionId);
        alert.setTitle("Suspicious Network Activity");
        alert.setDescription(description);
        alert.setSeverity(severity);
        alert.setRiskScore(riskScore);
        alert.setStatus("OPEN");
        alert.setCreatedAt(prediction.getPredictedAt());

        alertRepository.saveAndFlush(alert);
    }

    private String determineSeverity(BigDecimal riskScore) {

        if (riskScore.compareTo(new BigDecimal("90")) >= 0) {
            return "CRITICAL";
        }

        if (riskScore.compareTo(new BigDecimal("70")) >= 0) {
            return "HIGH";
        }

        if (riskScore.compareTo(new BigDecimal("40")) >= 0) {
            return "MEDIUM";
        }

        return "LOW";
    }

    private boolean matchesExistingEvent(
            NetworkFlow flow,
            MLPrediction prediction,
            CollectorFlowRequest request,
            String sourceIp,
            String destinationIp,
            OffsetDateTime flowTimestamp,
            String predictionLabel,
            double attackProbability) {

        BigDecimal expectedRiskScore =
                BigDecimal.valueOf(attackProbability * 100.0)
                        .setScale(6, RoundingMode.HALF_UP);

        return flow.getSourceAsset().getIpAddress().equals(sourceIp)
                && flow.getDestinationAsset().getIpAddress()
                        .equals(destinationIp)
                && Objects.equals(flow.getSourcePort(), request.sourcePort())
                && Objects.equals(
                        flow.getDestinationPort(),
                        request.destinationPort()
                )
                && flow.getProtocol().equals(
                        request.protocol().toUpperCase(Locale.ROOT)
                )
                && Objects.equals(flow.getBytesSent(), request.bytesSent())
                && Objects.equals(
                        flow.getBytesReceived(),
                        request.bytesReceived()
                )
                && Objects.equals(flow.getPackets(), request.packets())
                && Objects.equals(flow.getDuration(), request.duration())
                && flow.getTimestamp().toInstant()
                        .equals(flowTimestamp.toInstant())
                && prediction.getPrediction().equals(predictionLabel)
                && prediction.getModelName().equals(request.model().trim())
                && prediction.getRiskScore().compareTo(expectedRiskScore) == 0;
    }

    private CollectorFlowResponse buildResponse(
            NetworkFlow flow,
            MLPrediction prediction) {

        return new CollectorFlowResponse(
                flow.getId(),
                prediction.getId(),
                flow.getSourceAsset().getId(),
                flow.getDestinationAsset().getId(),
                prediction.getPrediction(),
                prediction.getRiskScore().doubleValue() / 100.0,
                prediction.getModelName(),
                flow.getTimestamp(),
                "SAVED"
        );
    }

    private Asset resolveAsset(String ipAddress) {

        List<Asset> matchingAssets =
                assetRepository.findAllByIpAddress(ipAddress);

        if (matchingAssets.size() > 1) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Multiple assets exist for IP address: " + ipAddress
            );
        }

        if (matchingAssets.size() == 1) {
            return matchingAssets.get(0);
        }

        Asset asset = new Asset();

        asset.setIpAddress(ipAddress);
        asset.setAssetType("NETWORK_ENDPOINT");
        asset.setCriticality("MEDIUM");

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

        asset.setCreatedAt(now);
        asset.setUpdatedAt(now);

        return assetRepository.saveAndFlush(asset);
    }

    private void validateRequest(CollectorFlowRequest request) {

        if (request == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Collector request cannot be empty"
            );
        }

        if (request.eventId() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Event ID cannot be empty"
            );
        }

        if (request.sourcePort() > 65535
                || request.destinationPort() > 65535) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid network port"
            );
        }

        if (!Double.isFinite(request.duration())
                || request.duration() < 0
                || !Double.isFinite(request.firstSeen())
                || request.firstSeen() < 0
                || request.firstSeen() > 253402300799.0) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid flow timestamp or duration"
            );
        }

        if (request.bytesSent() < 0
                || request.bytesReceived() < 0
                || request.packets() < 1) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid flow counters"
            );
        }

        if (!Double.isFinite(request.attackProbability())
                || request.attackProbability() < 0
                || request.attackProbability() > 1) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid attack probability"
            );
        }

        if (!request.prediction().equals("ATTACK")
                && !request.prediction().equals("BENIGN")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported prediction label"
            );
        }

        if (request.model().isBlank()
                || request.model().trim().length() > 100) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid model name"
            );
        }

        if (request.protocol().isBlank()
                || !List.of("TCP", "UDP", "ICMP", "OTHER")
                        .contains(request.protocol().toUpperCase(Locale.ROOT))) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported network protocol"
            );
        }
    }

    private String normalizeIp(String value) {

        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "IP address cannot be empty"
            );
        }

        String ip = value.trim();

        try {
            if (ip.contains(":")) {
                if (!ip.matches("[0-9a-fA-F:.]+")) {
                    throw new UnknownHostException();
                }
            } else {
                if (!ip.matches("[0-9.]+")) {
                    throw new UnknownHostException();
                }

                String[] octets = ip.split("\\.", -1);

                if (octets.length != 4) {
                    throw new UnknownHostException();
                }

                for (String octet : octets) {
                    if (octet.isEmpty()
                            || Integer.parseInt(octet) > 255) {
                        throw new UnknownHostException();
                    }
                }
            }

            return InetAddress.getByName(ip).getHostAddress();

        } catch (UnknownHostException | NumberFormatException exception) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid IP address"
            );
        }
    }
}
