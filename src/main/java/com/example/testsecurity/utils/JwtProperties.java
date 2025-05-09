package com.example.testsecurity.utils;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.temporal.ChronoUnit;

@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        String accessSecretKey,
        long accessTokenLifeTime,
        ChronoUnit accessUnit,

        String refreshSecretKey,
        long refreshTokenLifeTime,
        ChronoUnit refreshUnit
) {}
