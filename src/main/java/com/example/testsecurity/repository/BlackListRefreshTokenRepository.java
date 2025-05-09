package com.example.testsecurity.repository;

import com.example.testsecurity.entity.BlackListRefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface BlackListRefreshTokenRepository extends JpaRepository<BlackListRefreshTokenEntity, UUID> {
    Boolean existsByRefreshToken(String refreshToken);
    Boolean deleteByRefreshToken(String refreshToken);
    Optional<BlackListRefreshTokenEntity> findByRefreshToken(String refreshToken);
}
