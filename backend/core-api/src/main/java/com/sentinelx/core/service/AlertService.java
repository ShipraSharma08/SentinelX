package com.sentinelx.core.service;

import com.sentinelx.core.model.Alert;
import com.sentinelx.core.repository.AlertRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AlertService {

    private final AlertRepository alertRepository;

    public AlertService(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    @Transactional(readOnly = true)
    public List<Alert> findAll() {
        return alertRepository.findAll();
    }

    public Alert save(Alert alert) {
        return alertRepository.save(alert);
    }

    public Alert update(Alert alert) {
        return alertRepository.save(alert);
    }
}