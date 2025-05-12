package com.example.testsecurity.service.impl;

import com.example.testsecurity.entity.WhiteListRefreshTokenEntity;
import com.example.testsecurity.repository.WhiteListRefreshTokenRepository;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class WhiteListRefreshTokenServiceImpl {

    WhiteListRefreshTokenRepository whiteListRefreshTokenRepository;

    @PostConstruct
    private void initDeleteOldToken() {
        List<WhiteListRefreshTokenEntity> entities = whiteListRefreshTokenRepository.findAll();
        for (WhiteListRefreshTokenEntity entity : entities) {

            ZonedDateTime expiration = entity.getExpiration();
            ZonedDateTime now = ZonedDateTime.now();
            if (now.isAfter(expiration)) {
                whiteListRefreshTokenRepository.delete(entity);
            }
        }
    }

}
