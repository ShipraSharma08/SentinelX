package com.sentinelx.core.service;

import com.sentinelx.core.model.NetworkFlow;
import com.sentinelx.core.repository.NetworkFlowRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class NetworkFlowService {

    private final NetworkFlowRepository networkFlowRepository;

    public NetworkFlowService(NetworkFlowRepository networkFlowRepository) {
        this.networkFlowRepository = networkFlowRepository;
    }

    @Transactional(readOnly = true)
    public List<NetworkFlow> findAll() {
        return networkFlowRepository.findAll();
    }

    public NetworkFlow save(NetworkFlow flow) {
        return networkFlowRepository.save(flow);
    }

    public NetworkFlow update(NetworkFlow flow) {
        return networkFlowRepository.save(flow);
    }
}