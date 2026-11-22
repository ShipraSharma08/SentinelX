package com.sentinelx.core.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI sentinelXOpenAPI() {

        return new OpenAPI()
            .info(new Info()
                .title("SentinelX Core API")
                .version("1.0.0")
                .description("SentinelX security monitoring API"))

            .components(new Components()

                // JWT Authentication
                .addSecuritySchemes("Bearer Authentication",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT"))

                // Collector API Key Authentication
                .addSecuritySchemes("Collector API Key",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.HEADER)
                        .name("X-Collector-Key")
                        .description("Collector authentication API key")))

            // Default authentication for normal APIs
            .addSecurityItem(
                new SecurityRequirement()
                    .addList("Bearer Authentication"));
    }
}