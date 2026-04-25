package com.antivirus.license.dto;

import jakarta.validation.constraints.NotBlank;

public record ActivateLicenseRequest(
        @NotBlank String activationKey,
        @NotBlank String deviceMac,
        String deviceName
) {
}
