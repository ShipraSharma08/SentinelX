package com.sentinelx.core;

import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.repository.MLPredictionRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.transaction.AfterTransaction;
import org.springframework.test.context.transaction.BeforeTransaction;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import tools.jackson.databind.json.JsonMapper;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class MLPredictionIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MLPredictionRepository mlPredictionRepository;

    private static final JsonMapper JSON_MAPPER =
            JsonMapper.builder().build();

    private long baselinePredictionCount;

    private static final String[] FEATURE_NAMES = {
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Fwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Header Length.1",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min"
    };

    @BeforeTransaction
    void captureDatabaseBaseline() {
        baselinePredictionCount = mlPredictionRepository.count();
    }

    @AfterTransaction
    void verifyDatabaseRollback() {
        assertEquals(
                baselinePredictionCount,
                mlPredictionRepository.count(),
                "Integration test must not leave a prediction in the database"
        );
    }

    private String buildRequestBody() throws Exception {
        assertEquals(70, FEATURE_NAMES.length);

        Map<String, Double> features = new LinkedHashMap<>();

        for (String featureName : FEATURE_NAMES) {
            features.put(featureName, 0.0);
        }

        assertEquals(70, features.size());

        return JSON_MAPPER.writeValueAsString(
                Map.of("features", features)
        );
    }

    @Test
    @WithMockUser(roles = "SECURITY_ENGINEER")
    void shouldCallRealMlServiceAndPersistPrediction() throws Exception {

        String requestBody = buildRequestBody();

        mockMvc.perform(post("/api/ml/predict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.prediction").value("BENIGN"))
                .andExpect(jsonPath("$.model").value("web_coverage_candidate"))
                .andExpect(jsonPath("$.modelVersion").value("1.0"))
                .andExpect(jsonPath("$.confidence").isNumber())
                .andExpect(jsonPath("$.riskScore").isNumber())
                .andExpect(jsonPath("$.predictedAt").exists());

        assertEquals(
                baselinePredictionCount + 1,
                mlPredictionRepository.count(),
                "One prediction should be persisted inside the test transaction"
        );

        MLPrediction savedPrediction =
                mlPredictionRepository
                        .findTop10ByOrderByPredictedAtDesc()
                        .stream()
                        .findFirst()
                        .orElseThrow();

        assertEquals("BENIGN", savedPrediction.getPrediction());
        assertEquals(
                "web_coverage_candidate",
                savedPrediction.getModelName()
        );
        assertEquals("1.0", savedPrediction.getModelVersion());
        assertNotNull(savedPrediction.getConfidence());
        assertNotNull(savedPrediction.getRiskScore());
        assertNotNull(savedPrediction.getPredictedAt());
        assertNull(savedPrediction.getNetworkFlow());
    }
}
