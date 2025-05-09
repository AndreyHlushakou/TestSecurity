package com.example.testsecurity.repository;

import com.example.testsecurity.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleEntityRepository extends JpaRepository<RoleEntity, RoleEntity.RoleEnum> {

    default RoleEntity getRoleEntity(RoleEntity.RoleEnum roleEnum) {
        return findById(roleEnum).orElseThrow();
    }
}
