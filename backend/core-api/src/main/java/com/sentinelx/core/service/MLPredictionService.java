package com.sentinelx.core.service;

import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.repository.MLPredictionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class MLPredictionService {

    private final MLPredictionRepository mlPredictionRepository;

    public MLPredictionService(MLPredictionRepository mlPredictionRepository) {
        this.mlPredictionRepository = mlPredictionRepository;
    }

    @Transactional(readOnly = true)
    public List<MLPrediction> findAll() {
        return mlPredictionRepository.findAll();
    }

    public MLPrediction save(MLPrediction prediction) {
        return mlPredictionRepository.save(prediction);
    }

    public MLPrediction update(MLPrediction prediction) {
        return mlPredictionRepository.save(prediction);
    }
}