package com.antivirus.auth;

import com.antivirus.user.UserEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSessionRepository extends JpaRepository<UserSessionEntity, Long> {
    Optional<UserSessionEntity> findByRefreshToken(String refreshToken);
    Optional<UserSessionEntity> findByTokenJti(String tokenJti);
    List<UserSessionEntity> findAllByUserAndStatus(UserEntity user, SessionStatus status);
}
