package com.sentinelx.core.service;

import com.sentinelx.core.model.Alert;
import com.sentinelx.core.repository.AlertRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

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
}