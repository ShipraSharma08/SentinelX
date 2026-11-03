
package com.sentinelx.core.service;

import com.sentinelx.core.dto.ml.MLPredictionRequest;
import com.sentinelx.core.dto.ml.MLPredictionResponse;
import com.sentinelx.core.model.MLPrediction;
import com.sentinelx.core.model.NetworkFlow;
import com.sentinelx.core.repository.MLPredictionRepository;
import com.sentinelx.core.repository.NetworkFlowRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;

@Service
public class MLPredictionService {

    private final MLPredictionRepository mlPredictionRepository;
    private final NetworkFlowRepository networkFlowRepository;
    private final MLInferenceClient mlInferenceClient;

    public MLPredictionService(
            MLPredictionRepository mlPredictionRepository,
            NetworkFlowRepository networkFlowRepository,
            MLInferenceClient mlInferenceClient
    ) {
        this.mlPredictionRepository = mlPredictionRepository;
        this.networkFlowRepository = networkFlowRepository;
        this.mlInferenceClient = mlInferenceClient;
    }

    @Transactional(readOnly = true)
    public List<MLPrediction> findAll() {
        return mlPredictionRepository.findAll();
    }

    @Transactional
    public MLPrediction save(MLPrediction prediction) {
        return mlPredictionRepository.save(prediction);
    }

    @Transactional
    public MLPrediction update(MLPrediction prediction) {
        return mlPredictionRepository.save(prediction);
    }

    @Transactional
    public MLPrediction predictAndSave(
            MLPredictionRequest request
    ) {
        MLPredictionResponse response =
                mlInferenceClient.predict(request);

        if (response == null
                || response.prediction() == null
                || response.prediction().isBlank()
                || response.model() == null
                || response.model().isBlank()
                || response.attack_probability() == null) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "ML service returned an incomplete response"
            );
        }

        String predictionLabel = response.prediction()
                .trim()
                .toUpperCase(Locale.ROOT);

        if (!predictionLabel.equals("ATTACK")
                && !predictionLabel.equals("BENIGN")) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "ML service returned an unsupported prediction label"
            );
        }

        double attackProbability =
                response.attack_probability();

        if (!Double.isFinite(attackProbability)
                || attackProbability < 0.0
                || attackProbability > 1.0) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "ML service returned an invalid attack probability"
            );
        }

        MLPrediction prediction = new MLPrediction();

        prediction.setModelName(response.model().trim());
        prediction.setModelVersion("1.0");
        prediction.setPrediction(predictionLabel);

        double confidence = predictionLabel.equals("ATTACK")
                ? attackProbability
                : 1.0 - attackProbability;

        prediction.setConfidence(
                BigDecimal.valueOf(confidence)
        );

        prediction.setRiskScore(
                BigDecimal.valueOf(attackProbability * 100.0)
        );

        prediction.setPredictedAt(OffsetDateTime.now());

        if (request.networkFlowId() != null) {
            NetworkFlow flow = networkFlowRepository
                    .findById(request.networkFlowId())
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND,
                            "Network flow not found: "
                                    + request.networkFlowId()
                    ));

            prediction.setNetworkFlow(flow);
        }

        return mlPredictionRepository.save(prediction);
    }
}
