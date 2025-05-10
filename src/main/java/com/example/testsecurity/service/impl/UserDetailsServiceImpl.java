package com.example.testsecurity.service.impl;

import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import com.example.testsecurity.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@DependsOn({"roleEntityService"})
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserDetailsServiceImpl implements UserDetailsService {

    UserRepository userRepository;
    PasswordEncoder passwordEncoder;
    RoleEntityRepository roleEntityRepository;

    @PostConstruct
    public void initAdmin() {
        String admin = "admin";
        Optional<UserEntity> optionalUserEntity = userRepository.findByUsername(admin);
        if (optionalUserEntity.isEmpty()) {
            UserEntity user = new UserEntity();
            user.setUsername(admin);
            String hashedPassword = passwordEncoder.encode(admin);
            user.setPassword(hashedPassword);
            user.setAccountNonLocked(true);
//            user.setEnabled(false);
            user.addRole(roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_USER));
            user.addRole(roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_ADMIN));
            userRepository.save(user);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException(String.format("User %s not found", username)));
    }
}
