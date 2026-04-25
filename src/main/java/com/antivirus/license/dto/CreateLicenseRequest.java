package com.antivirus.license.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record CreateLicenseRequest(
        @NotNull Long productId,
        @NotNull Long typeId,
        @NotNull Long ownerId,
        @Min(1) int deviceCount,
        String description
) {
}
