package com.sentinelx.core.repository;

import com.sentinelx.core.model.Incident;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    long countByStatusIgnoreCase(String status);

    long countBySeverityIgnoreCase(String severity);

    @Query("""
            SELECT COUNT(i)
            FROM Incident i
            WHERE UPPER(i.status) NOT IN ('RESOLVED', 'CLOSED')
            """)
    long countActiveIncidents();

    List<Incident> findTop10ByOrderByDetectedAtDesc();
}
