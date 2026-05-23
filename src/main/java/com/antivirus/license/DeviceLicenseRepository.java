package com.antivirus.license;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceLicenseRepository extends JpaRepository<DeviceLicenseEntity, Long> {
    long countByLicense(LicenseEntity license);
    Optional<DeviceLicenseEntity> findFirstByLicense(LicenseEntity license);
}
