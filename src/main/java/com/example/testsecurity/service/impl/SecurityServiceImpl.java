package com.example.testsecurity.service.impl;

import com.example.testsecurity.dto.SignRequestDto;
import com.example.testsecurity.dto.TokenResponseDto;
import com.example.testsecurity.dto.UserDto;
import com.example.testsecurity.entity.BlackListRefreshTokenEntity;
import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import com.example.testsecurity.repository.UserRepository;
import com.example.testsecurity.service.SecurityService;
import com.example.testsecurity.service.TaskDeleteRefreshTokenService;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;

import static com.example.testsecurity.config.JwtUtils.*;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SecurityServiceImpl implements SecurityService {

    UserRepository userRepository;
    RoleEntityRepository roleEntityRepository;

    PasswordEncoder passwordEncoder;
    AuthenticationManager authenticationManager;

    TaskDeleteRefreshTokenService taskDeleteRefreshTokenService;

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
        user.setAccountNonLocked(false);
        user.setEnabled(false);
        userRepository.save(user);

        return ResponseEntity.ok("Success create user");
    }

    public ResponseEntity<?> allowSignInUser(String username, String token) {
        if (userRepository.existsByUsername(username)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is missing");
        }

        if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token in blacklist");
        }

        UserEntity user =userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        user.setAccountNonLocked(true);
        userRepository.save(user);
        return ResponseEntity.ok("Success unlock " + username);
    }

    @Override //индефикация+аунтеифкация=авторизация + проверка авторизован уже чи не
    public ResponseEntity<?> signIn(SignRequestDto signRequestDto) {
        Authentication authUser = UsernamePasswordAuthenticationToken.unauthenticated(signRequestDto.getUsername(), signRequestDto.getPassword());
        UserEntity user = (UserEntity) authUser.getPrincipal();
        if (!user.isEnabled()) {
            user.setEnabled(true);
            userRepository.save(user);

            Authentication authentication;
            try {
                authentication = authenticationManager.authenticate(authUser);
            } catch (AuthenticationException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage() + "\nIncorrect username or password.");
            }
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = generateToken(authentication, SecretEnum.ACCESS_SECRET);
            String refreshToken = generateToken(authentication, SecretEnum.REFRESH_SECRET);
            return ResponseEntity.ok(new TokenResponseDto(accessToken, refreshToken));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("The user is already authorized");
    }

    @Override
    public ResponseEntity<?> logout(Authentication authentication, String token) {
        if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token in blacklist");
        }

        if (isTokenCorrectType(token, SecretEnum.REFRESH_SECRET)) {
            UserEntity userEntity = (UserEntity) authentication.getPrincipal();
            userEntity.setEnabled(false);
            userRepository.save(userEntity);

            if (!taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
                BlackListRefreshTokenEntity blackListRefreshTokenEntity = new BlackListRefreshTokenEntity();
                blackListRefreshTokenEntity.setRefreshToken(token);
                Date expirationDate = extractExpiration(token);
                ZonedDateTime expiration = expirationDate.toInstant().atZone(ZoneId.systemDefault());
                blackListRefreshTokenEntity.setExpiration(expiration);
                taskDeleteRefreshTokenService.addToBlackListAndAndCreateTask(blackListRefreshTokenEntity);
            }

            return ResponseEntity.ok("User logout successfully");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token");
    }

    @Override
    public ResponseEntity<?> refreshAccessToken(Authentication authentication, String token) {
        if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token in blacklist");
        }

        if (isTokenCorrectType(token, SecretEnum.REFRESH_SECRET)) {
            String accessToken = generateToken(authentication, SecretEnum.ACCESS_SECRET);
            return ResponseEntity.ok(new TokenResponseDto(accessToken, null));
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token");
    }

    @Override
    public ResponseEntity<?> refreshTokens(Authentication authentication, String token) {
        if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token in blacklist");
        }

        if (isTokenCorrectType(token, SecretEnum.REFRESH_SECRET)) {
            String accessToken = generateToken(authentication, SecretEnum.ACCESS_SECRET);
            String refreshToken = generateToken(authentication, SecretEnum.REFRESH_SECRET);
            return ResponseEntity.ok(new TokenResponseDto(accessToken, refreshToken));
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect token or type token");
    }

    @Override
    public ResponseEntity<?> grantAdministratorRights(SignRequestDto signRequestDto, String token) {
        if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token in blacklist");
        }

        String username = signRequestDto.getUsername();
        if (username != null) {
            UserEntity user = userRepository.findByUsername(username).orElse(null);
            if (user != null) {
                user.addRole(roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_ADMIN));
                userRepository.save(user);
                return ResponseEntity.ok("Success updated!");
            } else return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User is missing in DB");

        } else return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username missing in request");

    }

    @Override
    public ResponseEntity<?> getListUserEntity(String token) {
        if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token in blacklist");
        }

        List<UserEntity> userEntities = roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_USER).getUserEntities().stream().toList();
        List<UserDto> userDtos = new ArrayList<>();
        for (UserEntity userEntity : userEntities) {
            UserDto userDto = UserDto.builder()
                    .username(userEntity.getUsername())
                    .password(userEntity.getPassword())
                    .roles(userEntity.getAuthorities().stream().map(RoleEntity::getAuthority).toList())
                    .build();
            userDtos.add(userDto);
        }
        return ResponseEntity.ok(userDtos);
    }

}
