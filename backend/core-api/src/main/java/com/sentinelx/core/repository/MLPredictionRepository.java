package com.sentinelx.core.repository;

import com.sentinelx.core.model.MLPrediction;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface MLPredictionRepository
        extends JpaRepository<MLPrediction, Long> {

    List<MLPrediction> findTop10ByOrderByPredictedAtDesc();

    long countByPredictionIgnoreCase(String prediction);

    Optional<MLPrediction> findByNetworkFlow_Id(Long networkFlowId);
}