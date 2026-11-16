
package com.sentinelx.core.repository;

import com.sentinelx.core.model.NetworkFlow;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface NetworkFlowRepository extends JpaRepository<NetworkFlow, Long> {

    List<NetworkFlow> findTop10ByOrderByTimestampDesc();

    Optional<NetworkFlow> findByEventId(UUID eventId);

    @Query(
        value = """
            SELECT 1
            FROM (
                SELECT pg_advisory_xact_lock(
                    hashtextextended(CAST(:eventId AS text), 0)
                )
            ) AS event_lock
            """,
        nativeQuery = true
    )
    Integer acquireEventLock(@Param("eventId") UUID eventId);
}
