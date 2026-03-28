package com.antivirus.auth;

import java.util.List;

public record RegisterResponse(
        String username,
        List<String> roles
) {
}
