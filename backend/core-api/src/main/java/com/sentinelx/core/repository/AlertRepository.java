package com.sentinelx.core.repository;

import com.sentinelx.core.model.Alert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    Page<Alert> findByStatusIgnoreCase(
            String status,
            Pageable pageable
    );

    Page<Alert> findBySeverityIgnoreCase(
            String severity,
            Pageable pageable
    );

    Page<Alert> findByStatusIgnoreCaseAndSeverityIgnoreCase(
            String status,
            String severity,
            Pageable pageable
    );
}