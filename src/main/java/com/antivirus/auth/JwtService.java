package com.antivirus.auth;

import com.antivirus.role.RoleEntity;
import com.antivirus.user.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    public static final String TOKEN_TYPE_ACCESS = "access";
    public static final String TOKEN_TYPE_REFRESH = "refresh";
    public static final String CLAIM_TOKEN_TYPE = "token_type";
    public static final String CLAIM_SESSION_ID = "session_id";
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_JTI = "jti";

    private final JwtProperties jwtProperties;
    private final SecretKey accessKey;
    private final SecretKey refreshKey;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.accessKey = Keys.hmacShaKeyFor(jwtProperties.accessSecret().getBytes(StandardCharsets.UTF_8));
        this.refreshKey = Keys.hmacShaKeyFor(jwtProperties.refreshSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(UserEntity user, long sessionId) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles().stream()
                .map(RoleEntity::getName)
                .map(Enum::name)
                .toList();
        return Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(jwtProperties.accessExpirationSeconds())))
                .claim(CLAIM_TOKEN_TYPE, TOKEN_TYPE_ACCESS)
                .claim(CLAIM_SESSION_ID, sessionId)
                .claim(CLAIM_ROLES, roles)
                .signWith(accessKey)
                .compact();
    }

    public String generateRefreshToken(UserEntity user, long sessionId, String tokenJti) {
        Instant now = Instant.now();
        String jti = tokenJti == null || tokenJti.isBlank() ? UUID.randomUUID().toString() : tokenJti;
        return Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(jwtProperties.refreshExpirationSeconds())))
                .claim(CLAIM_TOKEN_TYPE, TOKEN_TYPE_REFRESH)
                .claim(CLAIM_SESSION_ID, sessionId)
                .claim(CLAIM_JTI, jti)
                .signWith(refreshKey)
                .compact();
    }

    public Claims parseAndValidateAccessClaims(String token) {
        Claims claims = Jwts.parser().verifyWith(accessKey).build().parseSignedClaims(token).getPayload();
        if (!TOKEN_TYPE_ACCESS.equals(claims.get(CLAIM_TOKEN_TYPE, String.class))) {
            throw new JwtException("Token is not an access token");
        }
        return claims;
    }

    public Claims parseAndValidateRefreshClaims(String token) {
        Claims claims = Jwts.parser().verifyWith(refreshKey).build().parseSignedClaims(token).getPayload();
        if (!TOKEN_TYPE_REFRESH.equals(claims.get(CLAIM_TOKEN_TYPE, String.class))) {
            throw new JwtException("Token is not a refresh token");
        }
        return claims;
    }

    public String extractUsername(Claims claims) {
        return claims.getSubject();
    }

    public long extractSessionId(Claims claims) {
        Number sessionId = claims.get(CLAIM_SESSION_ID, Number.class);
        if (sessionId == null) {
            throw new JwtException("Missing session_id claim");
        }
        return sessionId.longValue();
    }

    public String extractJti(Claims claims) {
        String jti = claims.get(CLAIM_JTI, String.class);
        if (jti == null || jti.isBlank()) {
            throw new JwtException("Missing jti claim");
        }
        return jti;
    }
}
