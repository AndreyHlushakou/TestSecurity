package com.example.testsecurity.service.impl;

import com.example.testsecurity.dto.SignRequestDto;
import com.example.testsecurity.dto.TokenResponseDto;
import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import com.example.testsecurity.repository.UserRepository;
import com.example.testsecurity.service.SecurityService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static com.example.testsecurity.config.JwtUtils.SecretEnum.ACCESS_SECRET;
import static com.example.testsecurity.config.JwtUtils.SecretEnum.REFRESH_SECRET;
import static com.example.testsecurity.config.JwtUtils.generateToken;
import static com.example.testsecurity.config.JwtUtils.isTokenCorrectType;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SecurityServiceImpl implements SecurityService {

    UserRepository userRepository;
    RoleEntityRepository roleEntityRepository;

    PasswordEncoder passwordEncoder;
    AuthenticationManager authenticationManager;

    @Override //регистрация
    public ResponseEntity<?> signUp(SignRequestDto signRequestDto) {
        if (userRepository.existsByUsername(signRequestDto.getUsername())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username already exists");
        }

        UserEntity user = new UserEntity();
        user.setUsername(signRequestDto.getUsername());
        String hashedPassword = passwordEncoder.encode(signRequestDto.getPassword());
        user.setPassword(hashedPassword);
        user.addRole(roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_USER));
        userRepository.save(user);

        return ResponseEntity.ok("Success create user");
    }

    @Override //индефикация+аунтеифкация=авторизация + проверка авторизован уже чи не
    public ResponseEntity<?> signIn(SignRequestDto signRequestDto) {


        Authentication authentication;
        try {
            Authentication authUser = UsernamePasswordAuthenticationToken
                    .unauthenticated(signRequestDto.getUsername(), signRequestDto.getPassword());
            authentication = authenticationManager.authenticate(authUser);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = generateToken(authentication, ACCESS_SECRET);
        String refreshToken = generateToken(authentication, REFRESH_SECRET);
        return ResponseEntity.ok(new TokenResponseDto(accessToken, refreshToken));
    }

    @Override
    public ResponseEntity<?> logout(Authentication authentication, String token) {
        if (isTokenCorrectType(token, REFRESH_SECRET)) {
            return ResponseEntity.ok("User logout successfully");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token");
    }

    @Override //админ разблокировал юзера
    public ResponseEntity<?> unlockUser(String username) {
        return setLockingStateUser(username, true);
    }

    @Override //админ разблокировал юзера
    public ResponseEntity<?> lockUser(String username) {
        return setLockingStateUser(username, false);
    }

    private ResponseEntity<?> setLockingStateUser(String username, boolean isNonLock) {
        Optional<UserEntity> optionalUserEntity = userRepository.findByUsername(username);
        if (optionalUserEntity.isPresent()) {
            UserEntity user = optionalUserEntity.get();
            user.setAccountNonLocked(isNonLock);
            userRepository.save(user);
            return ResponseEntity.ok("Success unlock " + username);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is incorrect");
    }

//    @Override
//    public ResponseEntity<?> refreshAccessToken(Authentication authentication, String token) {
//        if (isTokenCorrectType(token, REFRESH_SECRET)) {
//            String accessToken = generateToken(authentication, ACCESS_SECRET);
//            return ResponseEntity.ok(new TokenResponseDto(accessToken, null));
//        }
//        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token");
//    }

    @Override
    public ResponseEntity<?> refreshTokens(Authentication authentication, String token) {
        if (isTokenCorrectType(token, REFRESH_SECRET)) {
            String accessToken = generateToken(authentication, ACCESS_SECRET);
            String refreshToken = generateToken(authentication, REFRESH_SECRET);
            return ResponseEntity.ok(new TokenResponseDto(accessToken, refreshToken));
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token");
    }

    @Override
    public ResponseEntity<?> grantAdministratorRights(String username) {
        if (username != null) {
            UserEntity user = userRepository.findByUsername(username).orElse(null);
            if (user != null) {
                user.addRole(roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_ADMIN));
                userRepository.save(user);
                return ResponseEntity.ok("Success updated!");
            } else return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User is missing in DB");

        } else return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username missing in request");

    }

}
