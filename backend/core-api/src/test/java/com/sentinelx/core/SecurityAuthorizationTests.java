package com.sentinelx.core;

import com.sentinelx.core.dto.alert.CreateAlertRequest;
import com.sentinelx.core.dto.ml.MLPredictionRequest;
import com.sentinelx.core.model.Alert;
import com.sentinelx.core.model.Asset;
import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.service.AlertService;
import com.sentinelx.core.service.AssetService;
import com.sentinelx.core.service.MLPredictionService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityAuthorizationTests {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AlertService alertService;

    @MockitoBean
    private AssetService assetService;

    @MockitoBean
    private MLPredictionService mlPredictionService;

    private static final String ALERT_REQUEST = """
            {
                "title": "RBAC Test Alert",
                "description": "Testing role permissions",
                "severity": "HIGH",
                "riskScore": 75.00,
                "status": "OPEN"
            }
            """;

    private static final String ASSET_REQUEST = """
            {
                "ipAddress": "192.168.1.100",
                "hostname": "rbac-test-host",
                "assetType": "SERVER"
            }
            """;

    private static final String ML_REQUEST = """
            {
                "features": {
                    "feature1": 1.0
                }
            }
            """;

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCanReadAlerts() throws Exception {
        when(alertService.getAllAlerts()).thenReturn(List.of());

        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotCreateAlert() throws Exception {
        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ALERT_REQUEST))
                .andExpect(status().isForbidden());

        verify(alertService, never())
                .createAlert(any(CreateAlertRequest.class));
    }

    @Test
    @WithMockUser(roles = "SOC_ANALYST")
    void socAnalystCanCreateAlert() throws Exception {
        Alert alert = new Alert();
        alert.setId(1L);
        alert.setTitle("RBAC Test Alert");
        alert.setDescription("Testing role permissions");
        alert.setSeverity("HIGH");
        alert.setRiskScore(new BigDecimal("75.00"));
        alert.setStatus("OPEN");

        when(alertService.createAlert(any(CreateAlertRequest.class)))
                .thenReturn(alert);

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ALERT_REQUEST))
                .andExpect(status().isCreated());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanCreateAlert() throws Exception {
        Alert alert = new Alert();
        alert.setId(2L);
        alert.setTitle("RBAC Test Alert");
        alert.setDescription("Testing admin permissions");
        alert.setSeverity("HIGH");
        alert.setRiskScore(new BigDecimal("75.00"));
        alert.setStatus("OPEN");

        when(alertService.createAlert(any(CreateAlertRequest.class)))
                .thenReturn(alert);

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ALERT_REQUEST))
                .andExpect(status().isCreated());
    }

    @Test
    void unauthenticatedUserCannotReadAlerts() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanCreateAsset() throws Exception {
        when(assetService.save(any(Asset.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        mockMvc.perform(post("/api/assets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ASSET_REQUEST))
                .andExpect(status().isOk());

        verify(assetService).save(any(Asset.class));
    }

    @Test
    @WithMockUser(roles = "SECURITY_ENGINEER")
    void securityEngineerCanCreateAsset() throws Exception {
        when(assetService.save(any(Asset.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        mockMvc.perform(post("/api/assets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ASSET_REQUEST))
                .andExpect(status().isOk());

        verify(assetService).save(any(Asset.class));
    }

    @Test
    @WithMockUser(roles = "SOC_ANALYST")
    void socAnalystCannotCreateAsset() throws Exception {
        mockMvc.perform(post("/api/assets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ASSET_REQUEST))
                .andExpect(status().isForbidden());

        verify(assetService, never()).save(any(Asset.class));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotGenerateMlPrediction() throws Exception {
        mockMvc.perform(post("/api/ml/predict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ML_REQUEST))
                .andExpect(status().isForbidden());

        verify(mlPredictionService, never())
                .predictAndSave(any(MLPredictionRequest.class));
    }

    @Test
    @WithMockUser(roles = "SECURITY_ENGINEER")
    void securityEngineerCanGenerateMlPrediction() throws Exception {
        MLPrediction prediction = new MLPrediction();
        prediction.setId(1L);
        prediction.setModelName("rbac-test-model");
        prediction.setModelVersion("1.0");
        prediction.setPrediction("BENIGN");
        prediction.setConfidence(new BigDecimal("0.950000"));
        prediction.setRiskScore(new BigDecimal("0.050000"));
        prediction.setPredictedAt(OffsetDateTime.now());

        when(mlPredictionService.predictAndSave(any(MLPredictionRequest.class)))
                .thenReturn(prediction);

        mockMvc.perform(post("/api/ml/predict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ML_REQUEST))
                .andExpect(status().isCreated());

        verify(mlPredictionService)
                .predictAndSave(any(MLPredictionRequest.class));
    }
}
