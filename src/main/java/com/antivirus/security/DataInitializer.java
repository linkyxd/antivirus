package com.antivirus.security;

import com.antivirus.role.RoleEntity;
import com.antivirus.role.RoleName;
import com.antivirus.role.RoleRepository;
import com.antivirus.user.UserEntity;
import com.antivirus.user.UserRepository;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed.admin.username:admin}")
    private String adminUsername;

    @Value("${app.seed.admin.password:admin12345}")
    private String adminPassword;

    @Value("${app.seed.user.username:user}")
    private String userUsername;

    @Value("${app.seed.user.password:user12345}")
    private String userPassword;

    public DataInitializer(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        RoleEntity roleUser = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseGet(() -> roleRepository.save(new RoleEntity(RoleName.ROLE_USER)));
        RoleEntity roleAdmin = roleRepository.findByName(RoleName.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(new RoleEntity(RoleName.ROLE_ADMIN)));

        userRepository.findByUsername(adminUsername)
                .orElseGet(() -> userRepository.save(createUser(adminUsername, adminPassword, Set.of(roleAdmin, roleUser))));
        userRepository.findByUsername(userUsername)
                .orElseGet(() -> userRepository.save(createUser(userUsername, userPassword, Set.of(roleUser))));
    }

    private UserEntity createUser(String username, String password, Set<RoleEntity> roles) {
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setEnabled(true);
        user.setRoles(roles);
        return user;
    }
}
