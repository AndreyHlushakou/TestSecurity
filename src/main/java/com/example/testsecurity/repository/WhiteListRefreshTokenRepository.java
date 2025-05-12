package com.example.testsecurity.repository;

import com.example.testsecurity.entity.WhiteListRefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface WhiteListRefreshTokenRepository extends JpaRepository<WhiteListRefreshTokenEntity, UUID> {
    @Transactional
    void deleteByRefreshToken(String refreshToken);
    Optional<WhiteListRefreshTokenEntity> findByRefreshToken(String refreshToken);
}
