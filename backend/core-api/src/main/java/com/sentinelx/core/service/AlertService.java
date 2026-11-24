package com.sentinelx.core.service;

import com.sentinelx.core.dto.alert.CreateAlertRequest;
import com.sentinelx.core.model.Alert;
import com.sentinelx.core.repository.AlertRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;

@Service
public class AlertService {

    private final AlertRepository alertRepository;

    public AlertService(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    public List<Alert> getAllAlerts() {
        return alertRepository.findAll(
                Sort.by(Sort.Direction.DESC, "createdAt")
        );
    }

    public Page<Alert> getAlerts(
            String status,
            String severity,
            int page,
            int size
    ) {

        if (page < 0) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Page number cannot be negative"
            );
        }

        if (size < 1 || size > 100) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Page size must be between 1 and 100"
            );
        }

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.DESC, "createdAt")
        );

        boolean hasStatus = status != null && !status.isBlank();
        boolean hasSeverity = severity != null && !severity.isBlank();

        if (hasStatus && hasSeverity) {
            return alertRepository.findByStatusIgnoreCaseAndSeverityIgnoreCase(
                    status.trim(),
                    severity.trim(),
                    pageable
            );
        }

        if (hasStatus) {
            return alertRepository.findByStatusIgnoreCase(
                    status.trim(),
                    pageable
            );
        }

        if (hasSeverity) {
            return alertRepository.findBySeverityIgnoreCase(
                    severity.trim(),
                    pageable
            );
        }

        return alertRepository.findAll(pageable);
    }

    public Alert getAlertById(Long id) {
        return alertRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Alert not found with id: " + id
                ));
    }

    /**
     * Creates a manually submitted alert.
     * Client-controlled fields are restricted through CreateAlertRequest.
     * Sensitive fields are always controlled by the backend.
     */
    public Alert createAlert(CreateAlertRequest request) {

        Alert alert = new Alert();

        alert.setTitle(request.title().trim());
        alert.setDescription(request.description());
        alert.setSeverity(request.severity().trim().toUpperCase(Locale.ROOT));
        alert.setRiskScore(request.riskScore());

        // Backend-controlled fields
        alert.setId(null);
        alert.setStatus("OPEN");
        alert.setCreatedAt(OffsetDateTime.now());
        alert.setAcknowledgedAt(null);
        alert.setResolvedAt(null);
        alert.setMlPredictionId(null);
        alert.setSecurityEvent(null);

        return alertRepository.save(alert);
    }

    /**
     * Acknowledges an alert.
     *
     * A resolved alert cannot be acknowledged.
     * Repeated acknowledgement requests are idempotent.
     * The original acknowledgement timestamp is preserved.
     */
    @Transactional
    public Alert acknowledgeAlert(Long id) {

        Alert alert = getAlertById(id);

        if ("RESOLVED".equalsIgnoreCase(alert.getStatus())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Resolved alert cannot be acknowledged"
            );
        }

        // Already acknowledged: do not overwrite the original timestamp.
        if ("ACKNOWLEDGED".equalsIgnoreCase(alert.getStatus())) {
            return alert;
        }

        alert.setStatus("ACKNOWLEDGED");
        alert.setAcknowledgedAt(OffsetDateTime.now());

        return alertRepository.save(alert);
    }

    /**
     * Resolves an alert.
     *
     * Repeated resolution requests are idempotent.
     * The original resolution timestamp is preserved.
     */
    @Transactional
    public Alert resolveAlert(Long id) {

        Alert alert = getAlertById(id);

        // Already resolved: preserve the original resolution timestamp.
        if ("RESOLVED".equalsIgnoreCase(alert.getStatus())) {
            return alert;
        }

        alert.setStatus("RESOLVED");
        alert.setResolvedAt(OffsetDateTime.now());

        return alertRepository.save(alert);
    }
}