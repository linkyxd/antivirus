package com.antivirus.license.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CheckLicenseRequest(
        @NotNull Long productId,
        @NotBlank String deviceMac
) {
}
