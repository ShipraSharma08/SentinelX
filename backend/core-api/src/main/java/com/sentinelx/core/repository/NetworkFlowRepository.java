package com.sentinelx.core.repository;

import com.sentinelx.core.model.NetworkFlow;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.OffsetDateTime;
import java.util.List;

public interface NetworkFlowRepository extends JpaRepository<NetworkFlow, Long> {

    List<NetworkFlow> findBySourceAsset_Id(Long sourceAssetId);

    List<NetworkFlow> findByDestinationAsset_Id(Long destinationAssetId);

    List<NetworkFlow> findByProtocol(String protocol);

    List<NetworkFlow> findByTimestampBetween(
            OffsetDateTime start,
            OffsetDateTime end
    );
}
