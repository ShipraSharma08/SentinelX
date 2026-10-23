package com.sentinelx.core;

import com.sentinelx.core.model.Alert;
import com.sentinelx.core.service.AlertService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
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
                .thenThrow(new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
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

    @Test
    void searchAlertsReturnsPaginatedResponse() throws Exception {
        Alert alert = createTestAlert(42L);
        Page<Alert> page = new PageImpl<>(
                List.of(alert),
                PageRequest.of(0, 2),
                5
        );

        when(alertService.getAlerts(isNull(), isNull(), eq(0), eq(2)))
                .thenReturn(page);

        mockMvc.perform(get("/api/alerts/search")
                        .param("page", "0")
                        .param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.totalPages").value(3))
                .andExpect(jsonPath("$.size").value(2));
    }

    @Test
    void searchAlertsPassesStatusFilterToService() throws Exception {
        when(alertService.getAlerts(eq("OPEN"), isNull(), eq(0), eq(20)))
                .thenReturn(new PageImpl<>(List.of(createTestAlert(42L))));

        mockMvc.perform(get("/api/alerts/search")
                        .param("status", "OPEN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].status").value("OPEN"));

    }

    @Test
    void searchAlertsPassesSeverityFilterToService() throws Exception {
        when(alertService.getAlerts(isNull(), eq("HIGH"), eq(0), eq(20)))
                .thenReturn(new PageImpl<>(List.of(createTestAlert(42L))));

        mockMvc.perform(get("/api/alerts/search")
                        .param("severity", "HIGH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].severity").value("HIGH"));
    }

    @Test
    void searchAlertsPassesCombinedFiltersToService() throws Exception {
        when(alertService.getAlerts(eq("OPEN"), eq("HIGH"), eq(0), eq(20)))
                .thenReturn(new PageImpl<>(List.of(createTestAlert(42L))));

        mockMvc.perform(get("/api/alerts/search")
                        .param("status", "OPEN")
                        .param("severity", "HIGH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].status").value("OPEN"))
                .andExpect(jsonPath("$.content[0].severity").value("HIGH"));
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