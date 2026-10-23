package com.sentinelx.core.service;

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

@Service
public class AlertService {

    private final AlertRepository alertRepository;

    public AlertService(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    public List<Alert> getAllAlerts() {
        return alertRepository.findAll();
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
                    "Page must be zero or greater"
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
            return alertRepository
                    .findByStatusIgnoreCaseAndSeverityIgnoreCase(
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

    public Alert createAlert(Alert alert) {
        return alertRepository.save(alert);
    }

    @Transactional
    public Alert acknowledgeAlert(Long id) {
        Alert alert = getAlertById(id);

        if ("RESOLVED".equalsIgnoreCase(alert.getStatus())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Resolved alerts cannot be acknowledged"
            );
        }

        if (!"ACKNOWLEDGED".equalsIgnoreCase(alert.getStatus())) {
            alert.setStatus("ACKNOWLEDGED");
            alert.setAcknowledgedAt(OffsetDateTime.now());
        }

        return alertRepository.save(alert);
    }

    @Transactional
    public Alert resolveAlert(Long id) {
        Alert alert = getAlertById(id);

        if (!"RESOLVED".equalsIgnoreCase(alert.getStatus())) {
            alert.setStatus("RESOLVED");
            alert.setResolvedAt(OffsetDateTime.now());
        }

        return alertRepository.save(alert);
    }
}