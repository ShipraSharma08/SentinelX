package com.sentinelx.core.controller;

import com.sentinelx.core.dto.ml.MLPredictionRequest;
import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.service.MLPredictionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/ml")
public class MLPredictionController {

    private final MLPredictionService mlPredictionService;

    public MLPredictionController(
            MLPredictionService mlPredictionService
    ) {
        this.mlPredictionService = mlPredictionService;
    }

    @PostMapping("/predict")
    public ResponseEntity<Map<String, Object>> predict(
            @Valid @RequestBody MLPredictionRequest request
    ) {
        MLPrediction saved =
                mlPredictionService.predictAndSave(request);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", saved.getId());
        response.put("prediction", saved.getPrediction());
        response.put("model", saved.getModelName());
        response.put("modelVersion", saved.getModelVersion());
        response.put("confidence", saved.getConfidence());
        response.put("riskScore", saved.getRiskScore());
        response.put("predictedAt", saved.getPredictedAt());

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }
}
