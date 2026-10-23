package com.sentinelx.core;

import com.sentinelx.core.model.Alert;
import com.sentinelx.core.service.AlertService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SentinelXCoreApiApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AlertService alertService;

    @Test
    void contextLoads() {
    }

    @Test
    void getAllAlertsReturnsOkAndJsonArray() throws Exception {
        when(alertService.getAllAlerts()).thenReturn(List.of());

        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void getAlertByIdReturnsAlertWhenFound() throws Exception {
        Alert alert = createTestAlert(42L);
        when(alertService.getAlertById(42L)).thenReturn(alert);

        mockMvc.perform(get("/api/alerts/42"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(42))
                .andExpect(jsonPath("$.title").value("Test Security Alert"))
                .andExpect(jsonPath("$.severity").value("HIGH"));
    }

    @Test
    void getMissingAlertReturnsNotFound() throws Exception {
        when(alertService.getAlertById(9999L))
                .thenThrow(new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND,
                        "Alert not found with id: 9999"
                ));

        mockMvc.perform(get("/api/alerts/9999"))
                .andExpect(status().isNotFound());
    }

    @Test
    void createAlertReturnsCreated() throws Exception {
        Alert createdAlert = createTestAlert(101L);
        when(alertService.createAlert(any(Alert.class))).thenReturn(createdAlert);

        String requestBody = """
                {
                    "title": "Test Security Alert",
                    "description": "Automated API integration test",
                    "severity": "HIGH",
                    "riskScore": 85.50,
                    "status": "OPEN"
                }
                """;

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(101))
                .andExpect(jsonPath("$.title").value("Test Security Alert"))
                .andExpect(jsonPath("$.severity").value("HIGH"));
    }

    private Alert createTestAlert(Long id) {
        Alert alert = new Alert();
        alert.setId(id);
        alert.setTitle("Test Security Alert");
        alert.setDescription("Automated API integration test");
        alert.setSeverity("HIGH");
        alert.setRiskScore(new BigDecimal("85.50"));
        alert.setStatus("OPEN");
        alert.setCreatedAt(OffsetDateTime.now());
        return alert;
    }
}