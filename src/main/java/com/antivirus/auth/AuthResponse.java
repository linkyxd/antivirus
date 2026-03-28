package com.antivirus.auth;

import java.util.List;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessExpiresIn,
        long refreshExpiresIn,
        List<String> roles
) {
}
