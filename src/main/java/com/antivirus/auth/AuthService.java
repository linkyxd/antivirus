package com.antivirus.auth;

import com.antivirus.role.RoleEntity;
import com.antivirus.role.RoleName;
import com.antivirus.role.RoleRepository;
import com.antivirus.user.UserEntity;
import com.antivirus.user.UserRepository;
import java.util.List;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenPairService tokenPairService;

    public AuthService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            TokenPairService tokenPairService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenPairService = tokenPairService;
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        Authentication auth = new UsernamePasswordAuthenticationToken(request.username(), request.password());
        authenticationManager.authenticate(auth);
        UserEntity user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return tokenPairService.issueForLogin(user);
    }

    @Transactional
    public AuthResponse refresh(RefreshRequest request) {
        return tokenPairService.rotateByRefreshToken(request.refreshToken());
    }

    @Transactional
    public void revoke(RefreshRequest request) {
        tokenPairService.revokeByRefreshToken(request.refreshToken());
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        userRepository.findByUsername(request.username()).ifPresent(existing -> {
            throw new IllegalArgumentException("Username is already taken");
        });
        RoleEntity userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new IllegalArgumentException("ROLE_USER is not configured"));

        UserEntity user = new UserEntity();
        user.setUsername(request.username());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setEnabled(true);
        user.setRoles(java.util.Set.of(userRole));
        userRepository.save(user);

        List<String> roles = user.getRoles().stream()
                .map(RoleEntity::getName)
                .map(Enum::name)
                .toList();
        return new RegisterResponse(user.getUsername(), roles);
    }
}
