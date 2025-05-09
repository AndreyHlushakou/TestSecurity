package com.example.testsecurity.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@Entity
@Table(name = "user_entity")
@DynamicInsert
@DynamicUpdate
@Getter
@Setter
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserEntity implements UserDetails {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.UUID)
    UUID id;

    @Column(name = "username", unique = true, nullable = false)
    String username;

    @Column(name = "password", nullable = false)
    String password;

    @Column(name = "enabled")
    Boolean enabled;

    @Column(name = "accountNonLocked")
    Boolean accountNonLocked;

    @ManyToMany(fetch = FetchType.EAGER) //, cascade = {CascadeType.PERSIST, CascadeType.MERGE}
    @JoinTable(name = "user_entity_role_entity",
            joinColumns = @JoinColumn(name = "user_entity_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_entity_id", referencedColumnName = "id"))
    Set<RoleEntity> authorities = new HashSet<>();

    public void addRole(RoleEntity roleEntity) {
        authorities.add(roleEntity);
        roleEntity.getUserEntities().add(this);
    }

    public void removeRole(RoleEntity roleEntity) {
        authorities.remove(roleEntity);
        roleEntity.getUserEntities().remove(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserEntity that = (UserEntity) o;
        return Objects.equals(id, that.id) && Objects.equals(username, that.username) && Objects.equals(password, that.password) && Objects.equals(enabled, that.enabled) && Objects.equals(accountNonLocked, that.accountNonLocked) && Objects.equals(authorities, that.authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, password, enabled, accountNonLocked);
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

}
