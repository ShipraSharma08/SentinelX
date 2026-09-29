package com.sentinelx.core.service;

import com.sentinelx.core.model.SecurityEvent;
import com.sentinelx.core.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;

    public SecurityEventService(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    @Transactional(readOnly = true)
    public Optional<SecurityEvent> findById(Long id) {
        return securityEventRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<SecurityEvent> findAll() {
        return securityEventRepository.findAll();
    }

    public SecurityEvent save(SecurityEvent event) {
        return securityEventRepository.save(event);
    }

    public SecurityEvent update(SecurityEvent event) {
        return securityEventRepository.save(event);
    }
}