package com.sentinelx.core.controller;

import com.sentinelx.core.dto.collector.CollectorFlowRequest;
import com.sentinelx.core.dto.collector.CollectorFlowResponse;
import com.sentinelx.core.service.CollectorIngestionService;

import jakarta.validation.Valid;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/collector")
public class CollectorFlowController {

    private final CollectorIngestionService collectorIngestionService;

    public CollectorFlowController(
            CollectorIngestionService collectorIngestionService) {
        this.collectorIngestionService = collectorIngestionService;
    }

    @PostMapping("/flows")
    @SecurityRequirement(name = "Collector API Key")
    public ResponseEntity<CollectorFlowResponse> ingestFlow(
            @Valid @RequestBody CollectorFlowRequest request) {

        CollectorFlowResponse response =
                collectorIngestionService.ingest(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }
}