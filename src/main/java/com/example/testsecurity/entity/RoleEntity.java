package com.example.testsecurity.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.security.core.GrantedAuthority;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "role_entity")
@DynamicInsert
@DynamicUpdate
@Getter
@Setter
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RoleEntity implements GrantedAuthority {

    public enum RoleEnum {
        ROLE_ADMIN,
        ROLE_USER;
    }

    @Id
    @Column(name = "id")
    @Enumerated(EnumType.STRING)
    RoleEnum roleEnum;

    @ManyToMany(mappedBy = "authorities", fetch = FetchType.EAGER)
    Set<UserEntity> userEntities = new HashSet<>();

    @Override
    public String getAuthority() {
        return roleEnum.name();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RoleEntity that = (RoleEntity) o;
        return roleEnum == that.roleEnum && Objects.equals(userEntities, that.userEntities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(roleEnum);
    }
}
