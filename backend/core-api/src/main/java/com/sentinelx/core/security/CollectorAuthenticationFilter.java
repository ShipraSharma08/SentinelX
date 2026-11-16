
package com.sentinelx.core.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@Component
public class CollectorAuthenticationFilter extends OncePerRequestFilter {

    private static final String COLLECTOR_ENDPOINT = "/api/collector/flows";
    private static final String API_KEY_HEADER = "X-Collector-Key";
    private static final String COLLECTOR_AUTHORITY = "COLLECTOR_INGEST";

    private final String configuredApiKey;

    public CollectorAuthenticationFilter(
            @Value("${sentinelx.collector.api-key:}") String configuredApiKey) {
        this.configuredApiKey = configuredApiKey;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !HttpMethod.POST.matches(request.getMethod())
                || !COLLECTOR_ENDPOINT.equals(request.getServletPath());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String suppliedApiKey = request.getHeader(API_KEY_HEADER);

        if (configuredApiKey == null
                || configuredApiKey.isBlank()
                || suppliedApiKey == null
                || suppliedApiKey.isBlank()
                || !constantTimeEquals(configuredApiKey, suppliedApiKey)) {

            SecurityContextHolder.clearContext();
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Collector authentication failed"
            );
            return;
        }

        var authentication = new UsernamePasswordAuthenticationToken(
                "sentinelx-collector",
                null,
                List.of(new SimpleGrantedAuthority(COLLECTOR_AUTHORITY))
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private boolean constantTimeEquals(String expected, String supplied) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] expectedHash = digest.digest(
                    expected.getBytes(StandardCharsets.UTF_8)
            );

            byte[] suppliedHash = digest.digest(
                    supplied.getBytes(StandardCharsets.UTF_8)
            );

            return MessageDigest.isEqual(expectedHash, suppliedHash);

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is unavailable",
                    exception
            );
        }
    }
}
