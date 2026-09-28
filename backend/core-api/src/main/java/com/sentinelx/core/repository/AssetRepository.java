package com.sentinelx.core.repository;

import com.sentinelx.core.model.Asset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AssetRepository extends JpaRepository<Asset, Long> {

    Optional<Asset> findByIpAddress(String ipAddress);

    Optional<Asset> findByHostname(String hostname);

    List<Asset> findByCriticality(String criticality);

    List<Asset> findByAssetType(String assetType);

    boolean existsByIpAddress(String ipAddress);
}
