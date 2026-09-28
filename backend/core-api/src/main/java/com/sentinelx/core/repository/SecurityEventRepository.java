package com.sentinelx.core.repository;

import com.sentinelx.core.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.OffsetDateTime;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findByEventType(String eventType);

    List<SecurityEvent> findBySeverity(String severity);

    List<SecurityEvent> findBySourceAsset_Id(Long sourceAssetId);

    List<SecurityEvent> findByDestinationAsset_Id(Long destinationAssetId);

    List<SecurityEvent> findByDetectedAtBetween(
            OffsetDateTime start,
            OffsetDateTime end
    );
}
