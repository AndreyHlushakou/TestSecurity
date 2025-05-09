package com.example.testsecurity.service.impl;

import com.example.testsecurity.entity.RoleEntity;
import com.example.testsecurity.repository.RoleEntityRepository;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RoleEntityService {

    RoleEntityRepository roleEntityRepository;

    @PostConstruct
    public void initRoleEntity() {
        for (RoleEntity.RoleEnum value : RoleEntity.RoleEnum.values()) {
            if (!roleEntityRepository.existsById(value)) {
                RoleEntity roleEntity = new RoleEntity();
                roleEntity.setRoleEnum(value);
                roleEntityRepository.save(roleEntity);
            }
        }
    }

}
