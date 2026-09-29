package com.sentinelx.core.service;

import com.sentinelx.core.model.ThreatIndicator;
import com.sentinelx.core.repository.ThreatIndicatorRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ThreatIndicatorService {

    private final ThreatIndicatorRepository threatIndicatorRepository;

    public ThreatIndicatorService(ThreatIndicatorRepository threatIndicatorRepository) {
        this.threatIndicatorRepository = threatIndicatorRepository;
    }

    @Transactional(readOnly = true)
    public List<ThreatIndicator> findAll() {
        return threatIndicatorRepository.findAll();
    }

    public ThreatIndicator save(ThreatIndicator indicator) {
        return threatIndicatorRepository.save(indicator);
    }

    public ThreatIndicator update(ThreatIndicator indicator) {
        return threatIndicatorRepository.save(indicator);
    }
}
