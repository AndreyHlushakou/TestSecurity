package com.example.testsecurity.service.impl;

import com.example.testsecurity.config.JwtUtils;
import com.example.testsecurity.dto.SignRequestDto;
import com.example.testsecurity.dto.TokenResponseDto;
import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.entity.WhiteListRefreshTokenEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import com.example.testsecurity.repository.UserRepository;
import com.example.testsecurity.repository.WhiteListRefreshTokenRepository;
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

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;

import static com.example.testsecurity.config.JwtUtils.SecretEnum.ACCESS_SECRET;
import static com.example.testsecurity.config.JwtUtils.SecretEnum.REFRESH_SECRET;
import static com.example.testsecurity.config.JwtUtils.generateToken;
import static com.example.testsecurity.config.JwtUtils.isTokenCorrectType;
import static com.example.testsecurity.utils.SecurityUtils.DEFAULT_ADMIN_NAME;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SecurityServiceImpl implements SecurityService {

    UserRepository userRepository;
    RoleEntityRepository roleEntityRepository;

    WhiteListRefreshTokenRepository whiteListRefreshTokenRepository;

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

    @Override //индефикация+аунтеифкация=авторизация
    public ResponseEntity<?> signIn(SignRequestDto signRequestDto) {
        Authentication authentication;
        try {
            Authentication authUser = UsernamePasswordAuthenticationToken
                    .unauthenticated(signRequestDto.getUsername(), signRequestDto.getPassword());
            authentication = authenticationManager.authenticate(authUser);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Error sign in: " + e.getMessage());
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = generateToken(authentication, ACCESS_SECRET);
        String refreshToken = generateToken(authentication, REFRESH_SECRET);

        saveRefreshTokenToWhiteList(authentication, refreshToken);

        return ResponseEntity.ok(new TokenResponseDto(accessToken, refreshToken));
    }

    private void saveRefreshTokenToWhiteList(Authentication authentication, String refreshToken) {
        UserEntity userEntity = (UserEntity) authentication.getPrincipal();

        Date expirationDate = JwtUtils.extractExpiration(refreshToken, REFRESH_SECRET);
        expirationDate = expirationDate == null ? new Date() : expirationDate;
        ZonedDateTime expiration = expirationDate.toInstant().atZone(ZoneId.systemDefault());

        WhiteListRefreshTokenEntity whiteListRefreshTokenEntity = whiteListRefreshTokenRepository
                .findById(userEntity.getId())
                .orElse(new WhiteListRefreshTokenEntity(userEntity.getId()));
        whiteListRefreshTokenEntity.setRefreshToken(refreshToken);
        whiteListRefreshTokenEntity.setExpiration(expiration);
        whiteListRefreshTokenRepository.save(whiteListRefreshTokenEntity);
    }

    @Override
    public ResponseEntity<?> logout(String token) {
        if (isTokenCorrectType(token, REFRESH_SECRET)) {
            whiteListRefreshTokenRepository.deleteByRefreshToken(token);
            return ResponseEntity.ok("User logout successfully");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token for logout");
    }

    @Override
    public ResponseEntity<?> refreshTokens(Authentication authentication, String token) {
        if (isTokenCorrectType(token, REFRESH_SECRET)) {
            String accessToken = generateToken(authentication, ACCESS_SECRET);
            String refreshToken = generateToken(authentication, REFRESH_SECRET);

            saveRefreshTokenToWhiteList(authentication, refreshToken);
            return ResponseEntity.ok(new TokenResponseDto(accessToken, refreshToken));
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token for refresh tokens");
    }


    @Override //админ разблокировал юзера
    public ResponseEntity<?> unlockUser(String username) {
        return setLockingStateUser(username, true);
    }

    @Override //админ разблокировал юзера
    public ResponseEntity<?> lockUser(String username) {
        if (username.equals(DEFAULT_ADMIN_NAME)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(DEFAULT_ADMIN_NAME + " can't be blocked");
        }
        return setLockingStateUser(username, false);
    }

    private ResponseEntity<?> setLockingStateUser(String username, boolean isNonLocked) {
        Optional<UserEntity> optionalUserEntity = userRepository.findByUsername(username);
        if (optionalUserEntity.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error " + (isNonLocked ? "unlock" : "lock") + " user. Username is incorrect");
        }

        UserEntity user = optionalUserEntity.get();
        user.setAccountNonLocked(isNonLocked);
        userRepository.save(user);

        return ResponseEntity.ok("Success " + (isNonLocked ? "unlock" : "lock") + " user " + username);
    }

    @Override
    public ResponseEntity<?> grantAdministratorRights(String username) {
        return administratorRights(username, UserEntity::addRole);
    }

    @Override
    public ResponseEntity<?> revokeAdministratorRights(String username) {
        if (username.equals(DEFAULT_ADMIN_NAME)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Administrator rights cannot be revoked from an " + DEFAULT_ADMIN_NAME);
        }
        return administratorRights(username, UserEntity::removeRole);
    }

    private ResponseEntity<?> administratorRights(String username, BiConsumer<UserEntity, RoleEntity> biConsumer) {
        if (username == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is missing from the request");
        }
        UserEntity user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is not in the DB");
        }

        RoleEntity roleEntity = roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_ADMIN);
        biConsumer.accept(user, roleEntity);
        userRepository.save(user);

        whiteListRefreshTokenRepository.deleteById(user.getId());

        List<String> listAuthority = user.getAuthorities().stream().map(RoleEntity::getAuthority).toList();
        return ResponseEntity.ok("Success. " + user.getUsername() + " has been " + listAuthority);
    }



}
