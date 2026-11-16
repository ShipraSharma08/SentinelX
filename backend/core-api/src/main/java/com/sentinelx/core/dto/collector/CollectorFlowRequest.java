
package com.sentinelx.core.dto.collector;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

public record CollectorFlowRequest(

        @JsonProperty("event_id")
        @NotNull
        UUID eventId,

        @JsonProperty("source_ip")
        @NotBlank
        String sourceIp,

        @JsonProperty("destination_ip")
        @NotBlank
        String destinationIp,

        @JsonProperty("source_port")
        @NotNull
        @Min(0)
        @Max(65535)
        Integer sourcePort,

        @JsonProperty("destination_port")
        @NotNull
        @Min(0)
        @Max(65535)
        Integer destinationPort,

        @JsonProperty("protocol")
        @NotBlank
        @Pattern(regexp = "TCP|UDP|ICMP|OTHER")
        String protocol,

        @JsonProperty("bytes_sent")
        @NotNull
        @Min(0)
        Long bytesSent,

        @JsonProperty("bytes_received")
        @NotNull
        @Min(0)
        Long bytesReceived,

        @JsonProperty("packets")
        @NotNull
        @Min(1)
        Long packets,

        @JsonProperty("duration")
        @NotNull
        @DecimalMin("0.0")
        Double duration,

        @JsonProperty("first_seen")
        @NotNull
        @DecimalMin("0.0")
        Double firstSeen,

        @JsonProperty("prediction")
        @NotBlank
        @Pattern(regexp = "ATTACK|BENIGN")
        String prediction,

        @JsonProperty("attack_probability")
        @NotNull
        @DecimalMin("0.0")
        @DecimalMax("1.0")
        Double attackProbability,

        @JsonProperty("model")
        @NotBlank
        String model

) {
}
