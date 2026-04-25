package com.antivirus.license;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface LicenseRepository extends JpaRepository<LicenseEntity, Long> {

    Optional<LicenseEntity> findByCode(String code);

    @Query("""
            SELECT l FROM LicenseEntity l
            JOIN DeviceLicenseEntity dl ON dl.license = l
            WHERE dl.device.id = :deviceId
              AND l.user.id = :userId
              AND l.product.id = :productId
              AND l.blocked = false
              AND l.endingDate > CURRENT_TIMESTAMP
            """)
    Optional<LicenseEntity> findActiveByDeviceUserAndProduct(
            @Param("deviceId") Long deviceId,
            @Param("userId") Long userId,
            @Param("productId") Long productId
    );
}
