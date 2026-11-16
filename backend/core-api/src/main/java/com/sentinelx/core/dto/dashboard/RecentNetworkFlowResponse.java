package com.sentinelx.core.dto.dashboard;

import java.time.OffsetDateTime;

public record RecentNetworkFlowResponse(
        Long id,
        String sourceIp,
        String destinationIp,
        Integer sourcePort,
        Integer destinationPort,
        String protocol,
        Long bytesSent,
        Long bytesReceived,
        Long packets,
        Double duration,
        OffsetDateTime timestamp
) {
}
