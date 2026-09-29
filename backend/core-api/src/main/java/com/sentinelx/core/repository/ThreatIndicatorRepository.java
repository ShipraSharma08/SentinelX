package com.sentinelx.core.repository;

import com.sentinelx.core.model.ThreatIndicator;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ThreatIndicatorRepository extends JpaRepository<ThreatIndicator, Long> {
}
