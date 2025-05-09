package com.example.testsecurity.service;

import com.example.testsecurity.entity.BlackListRefreshTokenEntity;

public interface TaskDeleteRefreshTokenService {
    boolean existsByRefreshToken(String refreshToken);
    void addToBlackListAndAndCreateTask(BlackListRefreshTokenEntity blackListRefreshTokenEntity);
}
