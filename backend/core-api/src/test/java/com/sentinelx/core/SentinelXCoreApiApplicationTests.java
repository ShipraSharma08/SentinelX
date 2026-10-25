package com.sentinelx.core;

import com.sentinelx.core.model.Alert;
import com.sentinelx.core.service.AlertService;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    @WithMockUser
    void getAllAlertsReturnsOk() throws Exception {
        Alert alert = createTestAlert(
                1L, "Suspicious Login", "HIGH"
        );

        when(alertService.getAllAlerts())
                .thenReturn(List.of(alert));

        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title")
                        .value("Suspicious Login"))
                .andExpect(jsonPath("$[0].severity")
                        .value("HIGH"));
    }

    @Test
    @WithMockUser
    void getAlertByIdReturnsAlert() throws Exception {
        Alert alert = createTestAlert(
                1L, "Suspicious Login", "HIGH"
        );

        when(alertService.getAlertById(1L))
                .thenReturn(alert);

        mockMvc.perform(get("/api/alerts/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.title")
                        .value("Suspicious Login"));
    }

    @Test
    @WithMockUser
    void getAlertByIdReturnsNotFoundForMissingAlert()
            throws Exception {

        when(alertService.getAlertById(999L))
                .thenThrow(new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Alert not found with id: 999"
                ));

        mockMvc.perform(get("/api/alerts/999"))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser
    void createAlertReturnsCreated() throws Exception {
        Alert createdAlert = createTestAlert(
                1L, "Suspicious Login", "HIGH"
        );

        when(alertService.createAlert(any(Alert.class)))
                .thenReturn(createdAlert);

        String requestBody = """
                {
                    "title": "Suspicious Login",
                    "description": "Multiple failed login attempts",
                    "severity": "HIGH",
                    "riskScore": 85.00,
                    "status": "OPEN"
                }
                """;

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title")
                        .value("Suspicious Login"))
                .andExpect(jsonPath("$.severity")
                        .value("HIGH"));
    }

    @Test
    @WithMockUser
    void getAlertsSearchReturnsPaginatedResults()
            throws Exception {

        Alert alert = createTestAlert(
                1L, "Suspicious Login", "HIGH"
        );

        when(alertService.getAlerts(
                eq(null), eq(null), eq(0), eq(2)
        )).thenReturn(new PageImpl<>(
                List.of(alert),
                PageRequest.of(0, 2),
                1
        ));

        mockMvc.perform(get("/api/alerts/search")
                        .param("page", "0")
                        .param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].title")
                        .value("Suspicious Login"))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1));
    }

    @Test
    @WithMockUser
    void getAlertsSearchFiltersByStatus() throws Exception {
        Alert alert = createTestAlert(
                1L, "Open Alert", "HIGH"
        );

        when(alertService.getAlerts(
                eq("OPEN"), eq(null), eq(0), eq(20)
        )).thenReturn(new PageImpl<>(
                List.of(alert),
                PageRequest.of(0, 20),
                1
        ));

        mockMvc.perform(get("/api/alerts/search")
                        .param("status", "OPEN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].status")
                        .value("OPEN"));
    }

    @Test
    @WithMockUser
    void getAlertsSearchFiltersBySeverity() throws Exception {
        Alert alert = createTestAlert(
                1L, "Critical Alert", "CRITICAL"
        );

        when(alertService.getAlerts(
                eq(null), eq("CRITICAL"), eq(0), eq(20)
        )).thenReturn(new PageImpl<>(
                List.of(alert),
                PageRequest.of(0, 20),
                1
        ));

        mockMvc.perform(get("/api/alerts/search")
                        .param("severity", "CRITICAL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].severity")
                        .value("CRITICAL"));
    }

    @Test
    @WithMockUser
    void getAlertsSearchFiltersByStatusAndSeverity()
            throws Exception {

        Alert alert = createTestAlert(
                1L, "Open High Alert", "HIGH"
        );

        when(alertService.getAlerts(
                eq("OPEN"), eq("HIGH"), eq(0), eq(2)
        )).thenReturn(new PageImpl<>(
                List.of(alert),
                PageRequest.of(0, 2),
                1
        ));

        mockMvc.perform(get("/api/alerts/search")
                        .param("status", "OPEN")
                        .param("severity", "HIGH")
                        .param("page", "0")
                        .param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].status")
                        .value("OPEN"))
                .andExpect(jsonPath("$.content[0].severity")
                        .value("HIGH"));
    }

    @Test
    @WithMockUser
    void createAlertRejectsBlankTitle() throws Exception {
        String requestBody = """
                {
                    "title": "   ",
                    "description": "Invalid alert",
                    "severity": "HIGH",
                    "riskScore": 50.00,
                    "status": "OPEN"
                }
                """;

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void createAlertRejectsInvalidSeverity() throws Exception {
        String requestBody = """
                {
                    "title": "Invalid severity test",
                    "description": "Invalid alert",
                    "severity": "URGENT",
                    "riskScore": 50.00,
                    "status": "OPEN"
                }
                """;

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void createAlertRejectsRiskScoreAbove100()
            throws Exception {

        String requestBody = """
                {
                    "title": "Invalid risk score test",
                    "description": "Invalid alert",
                    "severity": "HIGH",
                    "riskScore": 101.00,
                    "status": "OPEN"
                }
                """;

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }

    private Alert createTestAlert(
            Long id,
            String title,
            String severity
    ) {
        Alert alert = new Alert();

        alert.setId(id);
        alert.setTitle(title);
        alert.setDescription("Test alert description");
        alert.setSeverity(severity);
        alert.setRiskScore(new BigDecimal("85.00"));
        alert.setStatus("OPEN");

        return alert;
    }
}