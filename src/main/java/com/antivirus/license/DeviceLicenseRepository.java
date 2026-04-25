package com.antivirus.license;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceLicenseRepository extends JpaRepository<DeviceLicenseEntity, Long> {
    long countByLicense(LicenseEntity license);
}
