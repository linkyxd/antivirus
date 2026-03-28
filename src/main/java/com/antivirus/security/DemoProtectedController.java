package com.antivirus.security;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoProtectedController {

    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities()
        );
    }

    @GetMapping("/admin/ping")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> adminPing() {
        return Map.of("status", "admin-ok");
    }
}
