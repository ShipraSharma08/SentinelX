package com.sentinelx.core.service;

import com.sentinelx.core.model.Incident;
import com.sentinelx.core.repository.IncidentRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class IncidentService {

    private final IncidentRepository incidentRepository;

    public IncidentService(IncidentRepository incidentRepository) {
        this.incidentRepository = incidentRepository;
    }

    @Transactional(readOnly = true)
    public List<Incident> findAll() {
        return incidentRepository.findAll();
    }

    public Incident save(Incident incident) {
        return incidentRepository.save(incident);
    }

    public Incident update(Incident incident) {
        return incidentRepository.save(incident);
    }
}
