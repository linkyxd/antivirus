package com.antivirus.auth;

import com.antivirus.user.UserEntity;
import io.jsonwebtoken.JwtException;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            JwtService jwtService,
            JwtProperties jwtProperties
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public RefreshTokenEntity issue(UserEntity user) {
        String token = jwtService.generateRefreshToken(user, 0L, UUID.randomUUID().toString());
        RefreshTokenEntity entity = new RefreshTokenEntity();
        entity.setUser(user);
        entity.setToken(token);
        entity.setExpiryAt(Instant.now().plusSeconds(jwtProperties.refreshExpirationSeconds()));
        return refreshTokenRepository.save(entity);
    }

    @Transactional
    public void revokeAllActive(UserEntity user) {
        refreshTokenRepository.findAllByUserAndRevokedIsFalse(user).forEach(token -> token.setRevoked(true));
    }

    public RefreshTokenEntity validateActiveToken(String rawToken) {
        RefreshTokenEntity token = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));
        if (token.isRevoked() || token.getExpiryAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token is expired or revoked");
        }
        try {
            jwtService.parseAndValidateRefreshClaims(rawToken);
        } catch (JwtException ex) {
            throw new IllegalArgumentException("Refresh token is invalid");
        }
        return token;
    }
}
