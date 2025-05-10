package com.example.testsecurity.service.impl;

import com.example.testsecurity.dto.UserDto;
import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import com.example.testsecurity.service.CheckTokenService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CheckTokenServiceImpl implements CheckTokenService {

    RoleEntityRepository roleEntityRepository;

    @Override
    public String userLogged(Authentication authentication) {
        if (authentication == null) {
            return "You are not logged in";
        }
        return authentication.getPrincipal().toString();
    }

    @Override
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

}
