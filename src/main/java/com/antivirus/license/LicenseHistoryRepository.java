package com.antivirus.license;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LicenseHistoryRepository extends JpaRepository<LicenseHistoryEntity, Long> {
}
