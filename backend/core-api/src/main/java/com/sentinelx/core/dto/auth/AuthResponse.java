package com.sentinelx.core.dto.auth;

public record AuthResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        UserInfo user
) {
    public record UserInfo(
            Long id,
            String username,
            String email,
            String role
    ) {}
}
