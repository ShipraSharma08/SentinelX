
package com.sentinelx.core.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_ENTRIES = 10_000;

    private final Map<String, Window> windows = new HashMap<>();

    private record Limit(int maxRequests, long windowMillis) {}

    private static class Window {
        long startTime;
        int count;

        Window(long startTime) {
            this.startTime = startTime;
            this.count = 1;
        }
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        Limit limit = getLimit(request);

        if (limit == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientIp = request.getRemoteAddr();
        String key = request.getRequestURI() + ":" + clientIp;

        long now = System.currentTimeMillis();
        long retryAfterSeconds;

        synchronized (windows) {
            cleanupExpiredWindows(now);

            Window window = windows.get(key);

            if (window == null || now - window.startTime >= limit.windowMillis()) {
                if (windows.size() >= MAX_ENTRIES) {
                    response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                    response.setContentType("application/json");
                    response.getWriter().write(
                            "{\"error\":\"Rate limiter temporarily unavailable\"}"
                    );
                    return;
                }

                window = new Window(now);
                windows.put(key, window);
            } else {
                if (window.count >= limit.maxRequests()) {
                    retryAfterSeconds = Math.max(
                            1,
                            (window.startTime + limit.windowMillis() - now + 999) / 1000
                    );

                   response.setStatus(429);
                    response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");

                    response.getWriter().write(
                            "{\"error\":\"Too many requests. Please try again later.\"}"
                    );
                    return;
                }

                window.count++;
            }
        }

        filterChain.doFilter(request, response);
    }

    private Limit getLimit(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();

        if ("POST".equalsIgnoreCase(method) && "/api/auth/login".equals(path)) {
            return new Limit(5, Duration.ofMinutes(1).toMillis());
        }

        if ("POST".equalsIgnoreCase(method) && "/api/auth/register".equals(path)) {
            return new Limit(3, Duration.ofMinutes(10).toMillis());
        }

        if ("POST".equalsIgnoreCase(method) && "/api/ml/predict".equals(path)) {
            return new Limit(30, Duration.ofMinutes(1).toMillis());
        }

        if ("POST".equalsIgnoreCase(method) && "/api/collector/flows".equals(path)) {
            return new Limit(120, Duration.ofMinutes(1).toMillis());
        }

        return null;
    }

    private void cleanupExpiredWindows(long now) {
        Iterator<Map.Entry<String, Window>> iterator = windows.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, Window> entry = iterator.next();

            if (now - entry.getValue().startTime > Duration.ofMinutes(10).toMillis()) {
                iterator.remove();
            }
        }
    }
}
