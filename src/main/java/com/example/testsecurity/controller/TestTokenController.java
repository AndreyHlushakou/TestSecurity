package com.example.testsecurity.controller;

import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

import static com.example.testsecurity.utils.SecurityUtils.ROLE_ADMIN_str;

@RestController
@RequestMapping("/checkToken")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class TestTokenController {

    RoleEntityRepository roleEntityRepository;

    @GetMapping("/user")
    public ResponseEntity<?> userAccess(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You are not logged in");
        }

        UserEntity userEntity = (UserEntity) authentication.getPrincipal();
        UserDto userDto = UserDto.builder()
                .username(userEntity.getUsername())
                .password(userEntity.getPassword())
                .roles(userEntity.getAuthorities().stream().map(RoleEntity::getAuthority).toList())
                .build();
        return ResponseEntity.ok(userDto);
    }

    @PreAuthorize("hasAnyAuthority('" + ROLE_ADMIN_str + "')")
    @GetMapping("/getListUserEntity")
    public ResponseEntity<?> getListUserEntity() {
        List<UserEntity> userEntities =
                roleEntityRepository.getRoleEntity(RoleEntity.RoleEnum.ROLE_USER).getUserEntities().stream().toList();
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

    @Getter
    @Setter
    @NoArgsConstructor
    @FieldDefaults(level = AccessLevel.PRIVATE)
    @AllArgsConstructor
    @Builder
    private static class UserDto {
        String username;
        String password;
        List<String> roles;
    }

}
