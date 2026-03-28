package com.antivirus.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        String accessSecret,
        String refreshSecret,
        long accessExpirationSeconds,
        long refreshExpirationSeconds
) {
}
