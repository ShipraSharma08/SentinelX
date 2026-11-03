package com.sentinelx.core.service;

import com.sentinelx.core.dto.ml.MLPredictionRequest;
import com.sentinelx.core.dto.ml.MLPredictionResponse;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class MLInferenceClientTest {

    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0
        );
        server.start();

        baseUrl = "http://127.0.0.1:" +
                server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void predictReturnsResponseForSuccessfulRequest() {
        server.createContext("/predict", exchange -> {
            byte[] requestBody = exchange.getRequestBody().readAllBytes();
            String requestJson = new String(
                    requestBody, StandardCharsets.UTF_8
            );

            assertTrue(requestJson.contains("\"features\""));
            assertEquals("POST", exchange.getRequestMethod());

            byte[] responseBody = """
                    {
                      "prediction": "ATTACK",
                      "attack_probability": 0.91,
                      "model": "web_coverage_candidate"
                    }
                    """.getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set(
                    "Content-Type", "application/json"
            );
            exchange.sendResponseHeaders(200, responseBody.length);
            exchange.getResponseBody().write(responseBody);
            exchange.close();
        });

        MLInferenceClient client = new MLInferenceClient(baseUrl);

        MLPredictionResponse response = client.predict(
                new MLPredictionRequest(Map.of("feature_1", 1.5), null)
        );

        assertEquals("ATTACK", response.prediction());
        assertEquals(0.91, response.attack_probability(), 0.000001);
        assertEquals(
                "web_coverage_candidate", response.model()
        );
    }

    @Test
    void predictMapsNon2xxResponseToBadGatewayWithoutLeakingBody() {
        server.createContext("/predict", exchange -> {
            byte[] responseBody =
                    "sensitive-upstream-detail".getBytes(
                            StandardCharsets.UTF_8
                    );

            exchange.sendResponseHeaders(503, responseBody.length);
            exchange.getResponseBody().write(responseBody);
            exchange.close();
        });

        MLInferenceClient client = new MLInferenceClient(baseUrl);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> client.predict(
                        new MLPredictionRequest(
                                Map.of("feature_1", 1.5), null
                        )
                )
        );

        assertEquals(502, exception.getStatusCode().value());
        assertFalse(
                exception.getMessage().contains(
                        "sensitive-upstream-detail"
                )
        );
    }

    @Test
    void predictMapsMalformedJsonToBadGateway() {
        server.createContext("/predict", exchange -> {
            byte[] responseBody = "{invalid-json".getBytes(
                    StandardCharsets.UTF_8
            );

            exchange.sendResponseHeaders(200, responseBody.length);
            exchange.getResponseBody().write(responseBody);
            exchange.close();
        });

        MLInferenceClient client = new MLInferenceClient(baseUrl);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> client.predict(
                        new MLPredictionRequest(
                                Map.of("feature_1", 1.5), null
                        )
                )
        );

        assertEquals(502, exception.getStatusCode().value());
    }

    @Test
    void predictTimesOutWhenUpstreamDoesNotRespondInTime()
            throws InterruptedException {

        CountDownLatch requestReceived = new CountDownLatch(1);

        server.createContext("/predict", exchange -> {
            requestReceived.countDown();

            try {
                Thread.sleep(12_000);
                byte[] responseBody = """
                        {
                          "prediction": "BENIGN",
                          "attack_probability": 0.1,
                          "model": "test-model"
                        }
                        """.getBytes(StandardCharsets.UTF_8);

                exchange.sendResponseHeaders(200, responseBody.length);
                exchange.getResponseBody().write(responseBody);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } catch (IOException ignored) {
                // Expected if the client closes the connection on timeout.
            } finally {
                exchange.close();
            }
        });

        MLInferenceClient client = new MLInferenceClient(baseUrl);

        long startNanos = System.nanoTime();

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> client.predict(
                        new MLPredictionRequest(
                                Map.of("feature_1", 1.5), null
                        )
                )
        );

        long elapsedSeconds = TimeUnit.NANOSECONDS.toSeconds(
                System.nanoTime() - startNanos
        );

        assertTrue(
                requestReceived.await(1, TimeUnit.SECONDS),
                "Local test server should receive the request"
        );
        assertEquals(502, exception.getStatusCode().value());
        assertTrue(
                elapsedSeconds < 15,
                "Client should stop waiting after its configured timeout"
        );
    }
}
