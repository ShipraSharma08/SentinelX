package com.sentinelx.core.service;

import com.sentinelx.core.dto.ml.MLPredictionRequest;
import com.sentinelx.core.dto.ml.MLPredictionResponse;
import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.repository.MLPredictionRepository;
import com.sentinelx.core.repository.NetworkFlowRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MLPredictionServiceTest {

    @Mock
    private MLPredictionRepository mlPredictionRepository;

    @Mock
    private NetworkFlowRepository networkFlowRepository;

    @Mock
    private MLInferenceClient mlInferenceClient;

    @InjectMocks
    private MLPredictionService mlPredictionService;

    private MLPredictionRequest createRequest() {
        return new MLPredictionRequest(
                Map.of("feature_1", 1.5),
                null
        );
    }

    @Test
    void predictAndSavePersistsValidAttackPrediction() {
        MLPredictionRequest request = createRequest();

        when(mlInferenceClient.predict(request))
                .thenReturn(new MLPredictionResponse(
                        "ATTACK",
                        0.91,
                        "web_coverage_candidate"
                ));

        when(mlPredictionRepository.save(any(MLPrediction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        MLPrediction result =
                mlPredictionService.predictAndSave(request);

        ArgumentCaptor<MLPrediction> captor =
                ArgumentCaptor.forClass(MLPrediction.class);

        verify(mlPredictionRepository).save(captor.capture());

        MLPrediction saved = captor.getValue();

        assertSame(saved, result);
        assertEquals("ATTACK", saved.getPrediction());
        assertEquals(
                "web_coverage_candidate",
                saved.getModelName()
        );
        assertEquals("1.0", saved.getModelVersion());
        assertEquals(
                0,
                new BigDecimal("0.91").compareTo(saved.getConfidence())
        );
        assertEquals(
                0,
                new BigDecimal("91.0").compareTo(saved.getRiskScore())
        );
        assertNotNull(saved.getPredictedAt());

        verifyNoInteractions(networkFlowRepository);
    }

    @Test
    void predictAndSaveCalculatesBenignConfidenceCorrectly() {
        MLPredictionRequest request = createRequest();

        when(mlInferenceClient.predict(request))
                .thenReturn(new MLPredictionResponse(
                        "BENIGN",
                        0.10,
                        "web_coverage_candidate"
                ));

        when(mlPredictionRepository.save(any(MLPrediction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        MLPrediction result =
                mlPredictionService.predictAndSave(request);

        assertEquals("BENIGN", result.getPrediction());
        assertEquals(
                0,
                new BigDecimal("0.90").compareTo(result.getConfidence())
        );
        assertEquals(
                0,
                new BigDecimal("10.0").compareTo(result.getRiskScore())
        );

        verify(mlPredictionRepository).save(any(MLPrediction.class));
    }

    @Test
    void predictAndSaveRejectsNullInferenceResponse() {
        MLPredictionRequest request = createRequest();

        when(mlInferenceClient.predict(request)).thenReturn(null);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> mlPredictionService.predictAndSave(request)
        );

        assertEquals(
                HttpStatus.BAD_GATEWAY,
                exception.getStatusCode()
        );

        verify(mlPredictionRepository, never())
                .save(any(MLPrediction.class));
    }

    @Test
    void predictAndSaveRejectsUnsupportedPredictionLabel() {
        MLPredictionRequest request = createRequest();

        when(mlInferenceClient.predict(request))
                .thenReturn(new MLPredictionResponse(
                        "SUSPICIOUS",
                        0.75,
                        "test-model"
                ));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> mlPredictionService.predictAndSave(request)
        );

        assertEquals(
                HttpStatus.BAD_GATEWAY,
                exception.getStatusCode()
        );

        verify(mlPredictionRepository, never())
                .save(any(MLPrediction.class));
    }

    @ParameterizedTest
    @ValueSource(doubles = {-0.1, 1.1})
    void predictAndSaveRejectsProbabilityOutsideValidRange(
            double probability) {

        MLPredictionRequest request = createRequest();

        when(mlInferenceClient.predict(request))
                .thenReturn(new MLPredictionResponse(
                        "ATTACK",
                        probability,
                        "test-model"
                ));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> mlPredictionService.predictAndSave(request)
        );

        assertEquals(
                HttpStatus.BAD_GATEWAY,
                exception.getStatusCode()
        );

        verify(mlPredictionRepository, never())
                .save(any(MLPrediction.class));
    }

    @Test
    void predictAndSaveDoesNotPersistWhenInferenceFails() {
        MLPredictionRequest request = createRequest();

        when(mlInferenceClient.predict(request))
                .thenThrow(new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "ML service unavailable"
                ));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> mlPredictionService.predictAndSave(request)
        );

        assertEquals(
                HttpStatus.BAD_GATEWAY,
                exception.getStatusCode()
        );

        verify(mlPredictionRepository, never())
                .save(any(MLPrediction.class));
    }
}
