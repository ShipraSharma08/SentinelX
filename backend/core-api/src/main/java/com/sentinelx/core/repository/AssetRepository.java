
package com.sentinelx.core.repository;

import com.sentinelx.core.model.Asset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AssetRepository extends JpaRepository<Asset, Long> {

    Optional<Asset> findByIpAddress(String ipAddress);

    List<Asset> findAllByIpAddress(String ipAddress);

    boolean existsByIpAddress(String ipAddress);

    long countByCriticalityIgnoreCase(String criticality);

    List<Asset> findTop10ByOrderByCreatedAtDesc();
}
