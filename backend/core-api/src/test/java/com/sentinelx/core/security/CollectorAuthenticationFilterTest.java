
package com.sentinelx.core.security;

import jakarta.servlet.FilterChain;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class CollectorAuthenticationFilterTest {

    private static final String VALID_API_KEY = "test-collector-secret";

    private CollectorAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new CollectorAuthenticationFilter(VALID_API_KEY);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validApiKeyShouldAuthenticateCollector() throws Exception {
        MockHttpServletRequest request = createCollectorRequest();
        request.addHeader("X-Collector-Key", VALID_API_KEY);

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertTrue(chainInvoked.get());
        assertEquals(200, response.getStatus());
        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
        assertEquals("sentinelx-collector", authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(authority ->
                        authority.getAuthority().equals("COLLECTOR_INGEST")));
    }

    @Test
    void invalidApiKeyShouldReturnUnauthorized() throws Exception {
        MockHttpServletRequest request = createCollectorRequest();
        request.addHeader("X-Collector-Key", "wrong-secret");

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertFalse(chainInvoked.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void missingApiKeyShouldReturnUnauthorized() throws Exception {
        MockHttpServletRequest request = createCollectorRequest();

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertFalse(chainInvoked.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void emptyConfiguredApiKeyShouldRejectRequest() throws Exception {
        filter = new CollectorAuthenticationFilter("");

        MockHttpServletRequest request = createCollectorRequest();
        request.addHeader("X-Collector-Key", VALID_API_KEY);

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertFalse(chainInvoked.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void nullConfiguredApiKeyShouldRejectRequest() throws Exception {
        filter = new CollectorAuthenticationFilter(null);

        MockHttpServletRequest request = createCollectorRequest();
        request.addHeader("X-Collector-Key", VALID_API_KEY);

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertFalse(chainInvoked.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void getRequestShouldBypassCollectorAuthentication() throws Exception {
        MockHttpServletRequest request = createCollectorRequest();
        request.setMethod("GET");

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        assertTrue(chainInvoked.get());
        assertEquals(200, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void unrelatedEndpointShouldNotRunCollectorAuthentication() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setServletPath("/api/alerts");

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean chainInvoked = new AtomicBoolean(false);

        FilterChain chain = (req, res) -> chainInvoked.set(true);

        filter.doFilter(request, response, chain);

        assertTrue(chainInvoked.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    private MockHttpServletRequest createCollectorRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setServletPath("/api/collector/flows");
        return request;
    }
}
