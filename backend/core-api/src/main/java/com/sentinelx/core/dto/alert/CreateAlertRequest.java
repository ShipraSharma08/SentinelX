package com.sentinelx.core.dto.alert;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

public record CreateAlertRequest(

        @NotBlank(message = "Alert title is required")
        @Size(max = 255, message = "Title cannot exceed 255 characters")
        String title,

        @Size(max = 5000, message = "Description cannot exceed 5000 characters")
        String description,

        @NotBlank(message = "Severity is required")
        @Pattern(
                regexp = "(?i)LOW|MEDIUM|HIGH|CRITICAL",
                message = "Severity must be LOW, MEDIUM, HIGH, or CRITICAL"
        )
        String severity,

        @DecimalMin(value = "0.00", message = "Risk score cannot be below 0")
        @DecimalMax(value = "100.00", message = "Risk score cannot exceed 100")
        BigDecimal riskScore

) {
}
