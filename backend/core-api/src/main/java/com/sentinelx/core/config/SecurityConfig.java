
package com.sentinelx.core.config;

import com.sentinelx.core.security.CollectorAuthenticationFilter;
import com.sentinelx.core.security.JwtAuthenticationFilter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            CollectorAuthenticationFilter collectorAuthenticationFilter)
            throws Exception {

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .authorizeHttpRequests(auth -> auth

                // Preflight OPTIONS requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Public endpoints
                .requestMatchers(
                    "/api/auth/register",
                    "/api/auth/login",
                    "/actuator/health",
                    "/error",
                    "/swagger-ui.html",
                    "/swagger-ui/**",
                    "/v3/api-docs/**"
                ).permitAll()

                // Collector-only ingestion endpoint
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/collector/flows"
                ).hasAuthority("COLLECTOR_INGEST")

                // Read-only access
                .requestMatchers(
                    HttpMethod.GET,
                    "/api/dashboard/**",
                    "/api/alerts/**",
                    "/api/assets/**",
                    "/api/incidents/**"
                ).hasAnyRole(
                    "ADMIN",
                    "SOC_ANALYST",
                    "SECURITY_ENGINEER",
                    "VIEWER"
                )

                // Alert creation
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/alerts/**"
                ).hasAnyRole(
                    "ADMIN",
                    "SOC_ANALYST",
                    "SECURITY_ENGINEER"
                )

                // Alert acknowledgement and resolution
                .requestMatchers(
                    HttpMethod.PATCH,
                    "/api/alerts/**"
                ).hasAnyRole(
                    "ADMIN",
                    "SOC_ANALYST",
                    "SECURITY_ENGINEER"
                )

                // Asset creation
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/assets/**"
                ).hasAnyRole(
                    "ADMIN",
                    "SECURITY_ENGINEER"
                )

                // Asset updates
                .requestMatchers(
                    HttpMethod.PUT,
                    "/api/assets/**"
                ).hasAnyRole(
                    "ADMIN",
                    "SECURITY_ENGINEER"
                )

                // ML prediction generation
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/ml/predict"
                ).hasAnyRole(
                    "ADMIN",
                    "SOC_ANALYST",
                    "SECURITY_ENGINEER"
                )

                // Deny unlisted API endpoints
                .requestMatchers("/api/**").denyAll()

                .anyRequest().authenticated()
            )
            .addFilterBefore(
                jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(
                collectorAuthenticationFilter,
                JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of(
                "http://localhost:[*]",
                "http://127.0.0.1:[*]"
        ));
        configuration.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Prevent duplicate servlet-container registration.
     * Collector filter must run only inside Spring Security.
     */
    @Bean
    public FilterRegistrationBean<CollectorAuthenticationFilter>
    collectorFilterRegistration(CollectorAuthenticationFilter filter) {

        FilterRegistrationBean<CollectorAuthenticationFilter> registration =
                new FilterRegistrationBean<>(filter);

        registration.setEnabled(false);
        return registration;
    }
}
