package com.sentinelx.core.service;

import com.sentinelx.core.model.Asset;
import com.sentinelx.core.repository.AssetRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class AssetService {

    private final AssetRepository assetRepository;

    public AssetService(AssetRepository assetRepository) {
        this.assetRepository = assetRepository;
    }

    @Transactional(readOnly = true)
    public List<Asset> findAll() {
        return assetRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<Asset> findById(Long id) {
        return assetRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<Asset> findByIpAddress(String ipAddress) {
        return assetRepository.findByIpAddress(ipAddress);
    }

    public Asset save(Asset asset) {
        return assetRepository.save(asset);
    }

    public Asset update(Asset asset) {
        return assetRepository.save(asset);
    }
}