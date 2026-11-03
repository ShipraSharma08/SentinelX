package com.sentinelx.core.service;

import com.sentinelx.core.dto.ml.MLPredictionRequest;
import com.sentinelx.core.dto.ml.MLPredictionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

@Service
public class MLInferenceClient {

    private static final Logger log =
            LoggerFactory.getLogger(MLInferenceClient.class);

    private static final JsonMapper JSON_MAPPER =
            JsonMapper.builder().build();

    private static final Duration CONNECT_TIMEOUT =
            Duration.ofSeconds(3);

    private static final Duration REQUEST_TIMEOUT =
            Duration.ofSeconds(10);

    private final HttpClient httpClient;
    private final URI predictionUri;

    public MLInferenceClient(
            @Value("${sentinelx.ml.base-url}") String baseUrl
    ) {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(CONNECT_TIMEOUT)
                .build();

        this.predictionUri = URI.create(
                baseUrl.replaceAll("/+$", "") + "/predict"
        );
    }

    public MLPredictionResponse predict(
            MLPredictionRequest request
    ) {
        try {
            Map<String, Object> payload = Map.of(
                    "features", request.features()
            );

            String jsonPayload =
                    JSON_MAPPER.writeValueAsString(payload);

            byte[] bodyBytes =
                    jsonPayload.getBytes(StandardCharsets.UTF_8);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(predictionUri)
                    .version(HttpClient.Version.HTTP_1_1)
                    .timeout(REQUEST_TIMEOUT)
                    .header(
                            "Content-Type",
                            "application/json; charset=UTF-8"
                    )
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(
                            bodyBytes
                    ))
                    .build();

            log.debug(
                    "Sending ML inference request: uri={}, bodyBytes={}",
                    predictionUri,
                    bodyBytes.length
            );

            HttpResponse<String> response = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString(
                            StandardCharsets.UTF_8
                    )
            );

            log.debug(
                    "ML inference response received: status={}, responseBytes={}",
                    response.statusCode(),
                    response.body().getBytes(StandardCharsets.UTF_8).length
            );

            if (response.statusCode() < 200
                    || response.statusCode() >= 300) {

                log.warn(
                        "ML inference service returned HTTP status {}",
                        response.statusCode()
                );

                throw new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "ML inference service returned an unsuccessful response"
                );
            }

            return JSON_MAPPER.readValue(
                    response.body(),
                    MLPredictionResponse.class
            );

        } catch (ResponseStatusException exc) {
            throw exc;

        } catch (JacksonException exc) {
            log.warn(
                    "ML inference service returned invalid JSON: {}",
                    exc.getClass().getSimpleName()
            );

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "ML inference service returned an invalid response",
                    exc
            );

        } catch (IOException exc) {
            log.warn(
                    "ML inference communication failed: {}",
                    exc.getClass().getSimpleName()
            );

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "ML inference service is unavailable",
                    exc
            );

        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "ML inference request was interrupted",
                    exc
            );
        }
    }
}
