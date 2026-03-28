package com.antivirus;

import com.antivirus.auth.JwtProperties;
import com.antivirus.auth.JwtService;
import com.antivirus.role.RoleEntity;
import com.antivirus.role.RoleName;
import com.antivirus.user.UserEntity;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

    @Test
    void generatesAndParsesAccessToken() {
        JwtProperties properties = new JwtProperties(
                "AccessSecretForTestsNeedsThirtyTwoCharsOrMore12345",
                "RefreshSecretForTestsNeedsThirtyTwoCharsOrMore1234",
                900,
                604800
        );
        JwtService jwtService = new JwtService(properties);

        RoleEntity roleEntity = new RoleEntity(RoleName.ROLE_USER);
        UserEntity user = new UserEntity();
        user.setUsername("alice");
        user.setRoles(Set.of(roleEntity));

        String access = jwtService.generateAccessToken(user, 101L);
        var claims = jwtService.parseAndValidateAccessClaims(access);
        Assertions.assertEquals("alice", jwtService.extractUsername(claims));
        Assertions.assertEquals(101L, jwtService.extractSessionId(claims));
    }
}
