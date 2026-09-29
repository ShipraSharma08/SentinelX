package com.sentinelx.core.repository;

import com.sentinelx.core.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AlertRepository extends JpaRepository<Alert, Long> {
}