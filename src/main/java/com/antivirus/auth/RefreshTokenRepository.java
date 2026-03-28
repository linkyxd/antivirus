package com.antivirus.auth;

import com.antivirus.user.UserEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByToken(String token);
    List<RefreshTokenEntity> findAllByUserAndRevokedIsFalse(UserEntity user);
}
