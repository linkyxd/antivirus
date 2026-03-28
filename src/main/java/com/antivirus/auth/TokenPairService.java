package com.antivirus.auth;

import com.antivirus.role.RoleEntity;
import com.antivirus.user.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenPairService {

    private final UserSessionRepository userSessionRepository;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public TokenPairService(
            UserSessionRepository userSessionRepository,
            JwtService jwtService,
            JwtProperties jwtProperties
    ) {
        this.userSessionRepository = userSessionRepository;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public AuthResponse issueForLogin(UserEntity user) {
        revokeAllActiveForUser(user);
        UserSessionEntity session = createActiveSession(user);
        return buildAuthResponse(user, session);
    }

    @Transactional
    public AuthResponse rotateByRefreshToken(String refreshToken) {
        Claims claims = parseRefreshClaims(refreshToken);
        String tokenJti = jwtService.extractJti(claims);
        long tokenSessionId = jwtService.extractSessionId(claims);

        UserSessionEntity currentSession = userSessionRepository.findByTokenJti(tokenJti)
                .orElseThrow(() -> new UnauthorizedAuthException("Refresh session not found"));
        validateRefreshSession(currentSession, refreshToken, tokenSessionId);

        currentSession.setStatus(SessionStatus.ROTATED);
        userSessionRepository.save(currentSession);

        UserSessionEntity nextSession = createActiveSession(currentSession.getUser());
        currentSession.setReplacedBySessionId(nextSession.getId());

        return buildAuthResponse(currentSession.getUser(), nextSession);
    }

    @Transactional
    public void revokeByRefreshToken(String refreshToken) {
        Claims claims = parseRefreshClaims(refreshToken);
        String tokenJti = jwtService.extractJti(claims);
        UserSessionEntity session = userSessionRepository.findByTokenJti(tokenJti)
                .orElseThrow(() -> new UnauthorizedAuthException("Refresh session not found"));
        if (SessionStatus.ACTIVE.equals(session.getStatus())) {
            session.setStatus(SessionStatus.REVOKED);
            session.setRevokedAt(Instant.now());
        }
    }

    private Claims parseRefreshClaims(String refreshToken) {
        try {
            return jwtService.parseAndValidateRefreshClaims(refreshToken);
        } catch (JwtException ex) {
            throw new UnauthorizedAuthException("Refresh token is invalid");
        }
    }

    private void validateRefreshSession(UserSessionEntity session, String refreshToken, long tokenSessionId) {
        if (!SessionStatus.ACTIVE.equals(session.getStatus())) {
            throw new UnauthorizedAuthException("Refresh token is already used or revoked");
        }
        if (!session.getId().equals(tokenSessionId)) {
            throw new UnauthorizedAuthException("Refresh token session mismatch");
        }
        if (!session.getRefreshToken().equals(refreshToken)) {
            throw new UnauthorizedAuthException("Refresh token mismatch");
        }
        if (session.getExpiresAt().isBefore(Instant.now())) {
            session.setStatus(SessionStatus.EXPIRED);
            throw new UnauthorizedAuthException("Refresh token has expired");
        }
    }

    private UserSessionEntity createActiveSession(UserEntity user) {
        Instant now = Instant.now();
        UserSessionEntity session = new UserSessionEntity();
        session.setUser(user);
        session.setTokenJti(UUID.randomUUID().toString());
        session.setStatus(SessionStatus.ACTIVE);
        session.setIssuedAt(now);
        session.setExpiresAt(now.plusSeconds(jwtProperties.refreshExpirationSeconds()));
        session = userSessionRepository.save(session);

        String refreshToken = jwtService.generateRefreshToken(user, session.getId(), session.getTokenJti());
        session.setRefreshToken(refreshToken);
        return userSessionRepository.save(session);
    }

    private void revokeAllActiveForUser(UserEntity user) {
        userSessionRepository.findAllByUserAndStatus(user, SessionStatus.ACTIVE).forEach(session -> {
            session.setStatus(SessionStatus.REVOKED);
            session.setRevokedAt(Instant.now());
        });
    }

    private AuthResponse buildAuthResponse(UserEntity user, UserSessionEntity session) {
        String accessToken = jwtService.generateAccessToken(user, session.getId());
        List<String> roles = user.getRoles().stream()
                .map(RoleEntity::getName)
                .map(Enum::name)
                .toList();
        return new AuthResponse(
                accessToken,
                session.getRefreshToken(),
                "Bearer",
                jwtProperties.accessExpirationSeconds(),
                jwtProperties.refreshExpirationSeconds(),
                roles
        );
    }
}
