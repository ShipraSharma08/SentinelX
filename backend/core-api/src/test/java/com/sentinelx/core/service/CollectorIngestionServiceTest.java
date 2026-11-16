
package com.sentinelx.core.service;

import com.sentinelx.core.dto.collector.CollectorFlowRequest;
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CollectorIngestionServiceTest {

    @Mock
    private AssetRepository assetRepository;

    @Mock
    private NetworkFlowRepository networkFlowRepository;

    @Mock
    private MLPredictionRepository mlPredictionRepository;

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private AlertRepository alertRepository;

    @InjectMocks
    private CollectorIngestionService collectorIngestionService;

    private final AtomicLong assetIds = new AtomicLong(100);

    @BeforeEach
    void setUp() {
        assetIds.set(100);
    }

    private CollectorFlowRequest createRequest(
            String sourceIp,
            String destinationIp,
            String prediction,
            double attackProbability) {

        return createRequest(
                UUID.randomUUID(),
                sourceIp,
                destinationIp,
                prediction,
                attackProbability
        );
    }

    private CollectorFlowRequest createRequest(
            UUID eventId,
            String sourceIp,
            String destinationIp,
            String prediction,
            double attackProbability) {

        return new CollectorFlowRequest(
                eventId,
                sourceIp,
                destinationIp,
                54321,
                443,
                "TCP",
                1500L,
                2500L,
                20L,
                2.5,
                1700000000.0,
                prediction,
                attackProbability,
                " test-model "
        );
    }

    private Asset createAsset(String ipAddress, long id) {

        Asset asset = new Asset();

        asset.setId(id);
        asset.setIpAddress(ipAddress);
        asset.setAssetType("NETWORK_ENDPOINT");
        asset.setCriticality("MEDIUM");

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

        asset.setCreatedAt(now);
        asset.setUpdatedAt(now);

        return asset;
    }

    private void mockAssetCreation() {

        when(assetRepository.saveAndFlush(any(Asset.class)))
                .thenAnswer(invocation -> {
                    Asset asset = invocation.getArgument(0);
                    asset.setId(assetIds.incrementAndGet());
                    return asset;
                });
    }

    private void mockFlowAndPredictionPersistence() {

        when(networkFlowRepository.saveAndFlush(any(NetworkFlow.class)))
                .thenAnswer(invocation -> {
                    NetworkFlow flow = invocation.getArgument(0);
                    ReflectionTestUtils.setField(flow, "id", 50L);
                    return flow;
                });

        when(mlPredictionRepository.saveAndFlush(any(MLPrediction.class)))
                .thenAnswer(invocation -> {
                    MLPrediction prediction = invocation.getArgument(0);
                    prediction.setId(70L);
                    return prediction;
                });
    }

    private NetworkFlow createExistingFlow(
            UUID eventId,
            Asset sourceAsset,
            Asset destinationAsset) {

        NetworkFlow flow = new NetworkFlow();

        ReflectionTestUtils.setField(flow, "id", 50L);

        flow.setEventId(eventId);
        flow.setSourceAsset(sourceAsset);
        flow.setDestinationAsset(destinationAsset);
        flow.setSourcePort(54321);
        flow.setDestinationPort(443);
        flow.setProtocol("TCP");
        flow.setBytesSent(1500L);
        flow.setBytesReceived(2500L);
        flow.setPackets(20L);
        flow.setDuration(2.5);
        flow.setTimestamp(
                OffsetDateTime.ofInstant(
                        java.time.Instant.ofEpochMilli(1700000000000L),
                        ZoneOffset.UTC
                )
        );

        return flow;
    }

    private MLPrediction createExistingPrediction(NetworkFlow flow) {

        MLPrediction prediction = new MLPrediction();

        prediction.setId(70L);
        prediction.setNetworkFlow(flow);
        prediction.setPrediction("ATTACK");
        prediction.setModelName("test-model");
        prediction.setModelVersion("1.0");
        prediction.setConfidence(new BigDecimal("0.910000"));
        prediction.setRiskScore(new BigDecimal("91.000000"));
        prediction.setPredictedAt(OffsetDateTime.now(ZoneOffset.UTC));

        return prediction;
    }

    @Test
    void ingestShouldPersistAttackFlowPredictionSecurityEventAndAlert() {

        CollectorFlowRequest request = createRequest(
                "192.0.2.10",
                "192.0.2.20",
                "ATTACK",
                0.91
        );

        when(assetRepository.findAllByIpAddress("192.0.2.10"))
                .thenReturn(List.of());

        when(assetRepository.findAllByIpAddress("192.0.2.20"))
                .thenReturn(List.of());

        mockAssetCreation();
        mockFlowAndPredictionPersistence();

        when(securityEventRepository.saveAndFlush(any(SecurityEvent.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        when(alertRepository.saveAndFlush(any(Alert.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = collectorIngestionService.ingest(request);

        assertNotNull(response);
        assertEquals("ATTACK", response.prediction());
        assertEquals(50L, response.flowId());
        assertEquals(70L, response.predictionId());

        ArgumentCaptor<SecurityEvent> eventCaptor =
                ArgumentCaptor.forClass(SecurityEvent.class);

        verify(securityEventRepository)
                .saveAndFlush(eventCaptor.capture());

        SecurityEvent event = eventCaptor.getValue();

        assertEquals("ML_ATTACK_DETECTION", event.getEventType());
        assertEquals("CRITICAL", event.getSeverity());
        assertEquals("192.0.2.10", event.getSourceIp());
        assertEquals("192.0.2.20", event.getDestinationIp());
        assertEquals(54321, event.getSourcePort());
        assertEquals(443, event.getDestinationPort());
        assertEquals("TCP", event.getProtocol());
        assertNotNull(event.getDetectedAt());

        ArgumentCaptor<Alert> alertCaptor =
                ArgumentCaptor.forClass(Alert.class);

        verify(alertRepository)
                .saveAndFlush(alertCaptor.capture());

        Alert alert = alertCaptor.getValue();

        assertSame(event, alert.getSecurityEvent());
        assertEquals(70L, alert.getMlPredictionId());
        assertEquals("Suspicious Network Activity", alert.getTitle());
        assertEquals("CRITICAL", alert.getSeverity());
        assertEquals("OPEN", alert.getStatus());

        assertEquals(
                0,
                new BigDecimal("91.00").compareTo(alert.getRiskScore())
        );

        verify(alertRepository).existsByMlPredictionId(70L);
    }

    @Test
    void ingestShouldNotCreateAlertForBenignPrediction() {

        CollectorFlowRequest request = createRequest(
                "192.0.2.10",
                "192.0.2.20",
                "BENIGN",
                0.10
        );

        when(assetRepository.findAllByIpAddress("192.0.2.10"))
                .thenReturn(List.of());

        when(assetRepository.findAllByIpAddress("192.0.2.20"))
                .thenReturn(List.of());

        mockAssetCreation();
        mockFlowAndPredictionPersistence();

        var response = collectorIngestionService.ingest(request);

        assertNotNull(response);
        assertEquals("BENIGN", response.prediction());

        verify(networkFlowRepository).saveAndFlush(any(NetworkFlow.class));
        verify(mlPredictionRepository).saveAndFlush(any(MLPrediction.class));

        verifyNoInteractions(securityEventRepository);
        verifyNoInteractions(alertRepository);
    }

    @Test
    void ingestShouldReturnExistingRecordsForIdenticalRetry() {

        UUID eventId = UUID.randomUUID();

        CollectorFlowRequest request = createRequest(
                eventId,
                "192.0.2.10",
                "192.0.2.20",
                "ATTACK",
                0.91
        );

        Asset sourceAsset = createAsset("192.0.2.10", 1);
        Asset destinationAsset = createAsset("192.0.2.20", 2);

        NetworkFlow existingFlow = createExistingFlow(
                eventId,
                sourceAsset,
                destinationAsset
        );

        MLPrediction existingPrediction =
                createExistingPrediction(existingFlow);

        when(networkFlowRepository.findByEventId(eventId))
                .thenReturn(Optional.of(existingFlow));

        when(mlPredictionRepository.findByNetworkFlow_Id(50L))
                .thenReturn(Optional.of(existingPrediction));

        var response = collectorIngestionService.ingest(request);

        assertNotNull(response);
        assertEquals(50L, response.flowId());
        assertEquals(70L, response.predictionId());
        assertEquals("ATTACK", response.prediction());
        assertEquals("SAVED", response.status());

        verify(networkFlowRepository).acquireEventLock(eventId);

        verify(networkFlowRepository, never())
                .saveAndFlush(any(NetworkFlow.class));

        verify(mlPredictionRepository, never())
                .saveAndFlush(any(MLPrediction.class));

        verifyNoInteractions(assetRepository);
        verifyNoInteractions(securityEventRepository);
        verifyNoInteractions(alertRepository);
    }

    @Test
    void ingestShouldRejectSameEventIdWithDifferentPayload() {

        UUID eventId = UUID.randomUUID();

        CollectorFlowRequest changedRequest = createRequest(
                eventId,
                "192.0.2.10",
                "192.0.2.20",
                "ATTACK",
                0.75
        );

        Asset sourceAsset = createAsset("192.0.2.10", 1);
        Asset destinationAsset = createAsset("192.0.2.20", 2);

        NetworkFlow existingFlow = createExistingFlow(
                eventId,
                sourceAsset,
                destinationAsset
        );

        MLPrediction existingPrediction =
                createExistingPrediction(existingFlow);

        when(networkFlowRepository.findByEventId(eventId))
                .thenReturn(Optional.of(existingFlow));

        when(mlPredictionRepository.findByNetworkFlow_Id(50L))
                .thenReturn(Optional.of(existingPrediction));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> collectorIngestionService.ingest(changedRequest)
        );

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());

        verify(networkFlowRepository).acquireEventLock(eventId);

        verify(networkFlowRepository, never())
                .saveAndFlush(any(NetworkFlow.class));

        verify(mlPredictionRepository, never())
                .saveAndFlush(any(MLPrediction.class));

        verifyNoInteractions(assetRepository);
        verifyNoInteractions(securityEventRepository);
        verifyNoInteractions(alertRepository);
    }

    @Test
    void ingestShouldReuseExistingAssets() {

        CollectorFlowRequest request = createRequest(
                "192.0.2.10",
                "192.0.2.20",
                "BENIGN",
                0.10
        );

        Asset sourceAsset = createAsset("192.0.2.10", 1);
        Asset destinationAsset = createAsset("192.0.2.20", 2);

        when(assetRepository.findAllByIpAddress("192.0.2.10"))
                .thenReturn(List.of(sourceAsset));

        when(assetRepository.findAllByIpAddress("192.0.2.20"))
                .thenReturn(List.of(destinationAsset));

        mockFlowAndPredictionPersistence();

        collectorIngestionService.ingest(request);

        verify(assetRepository, never()).saveAndFlush(any(Asset.class));

        ArgumentCaptor<NetworkFlow> flowCaptor =
                ArgumentCaptor.forClass(NetworkFlow.class);

        verify(networkFlowRepository).saveAndFlush(flowCaptor.capture());

        assertSame(sourceAsset, flowCaptor.getValue().getSourceAsset());
        assertSame(destinationAsset, flowCaptor.getValue().getDestinationAsset());
    }

    @Test
    void ingestShouldReuseAssetWhenSourceAndDestinationIpAreSame() {

        String sameIp = "192.0.2.10";

        CollectorFlowRequest request = createRequest(
                sameIp,
                sameIp,
                "BENIGN",
                0.10
        );

        Asset existingAsset = createAsset(sameIp, 101);

        when(assetRepository.findAllByIpAddress(sameIp))
                .thenReturn(List.of(existingAsset));

        mockFlowAndPredictionPersistence();

        collectorIngestionService.ingest(request);

        verify(assetRepository, never()).saveAndFlush(any(Asset.class));

        ArgumentCaptor<NetworkFlow> flowCaptor =
                ArgumentCaptor.forClass(NetworkFlow.class);

        verify(networkFlowRepository).saveAndFlush(flowCaptor.capture());

        assertSame(
                flowCaptor.getValue().getSourceAsset(),
                flowCaptor.getValue().getDestinationAsset()
        );
    }

    @Test
    void ingestShouldRejectMultipleAssetsForSameIp() {

        CollectorFlowRequest request = createRequest(
                "192.0.2.10",
                "192.0.2.20",
                "ATTACK",
                0.91
        );

        when(assetRepository.findAllByIpAddress("192.0.2.10"))
                .thenReturn(List.of(
                        createAsset("192.0.2.10", 1),
                        createAsset("192.0.2.10", 2)
                ));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> collectorIngestionService.ingest(request)
        );

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());

        verify(networkFlowRepository).acquireEventLock(request.eventId());

        verify(networkFlowRepository, never())
                .saveAndFlush(any(NetworkFlow.class));

        verifyNoInteractions(mlPredictionRepository);
        verifyNoInteractions(securityEventRepository);
        verifyNoInteractions(alertRepository);
    }

    @Test
    void ingestShouldRejectInvalidIpAddress() {

        CollectorFlowRequest request = createRequest(
                "999.999.999.999",
                "192.0.2.20",
                "ATTACK",
                0.91
        );

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> collectorIngestionService.ingest(request)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());

        verifyNoInteractions(assetRepository);

        verify(networkFlowRepository)
                .acquireEventLock(request.eventId());

        verify(networkFlowRepository, never())
                .findByEventId(any(UUID.class));

        verifyNoInteractions(mlPredictionRepository);
        verifyNoInteractions(securityEventRepository);
        verifyNoInteractions(alertRepository);
    }

    @Test
    void ingestShouldRejectInvalidAttackProbability() {

        CollectorFlowRequest request = createRequest(
                "192.0.2.10",
                "192.0.2.20",
                "ATTACK",
                1.5
        );

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> collectorIngestionService.ingest(request)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());

        verifyNoInteractions(assetRepository);
        verifyNoInteractions(networkFlowRepository);
        verifyNoInteractions(mlPredictionRepository);
        verifyNoInteractions(securityEventRepository);
        verifyNoInteractions(alertRepository);
    }
}
