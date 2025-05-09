package com.example.testsecurity.utils;

import java.util.function.UnaryOperator;

public final class SecurityUtils {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final UnaryOperator<String> GET_BEARER_TOKEN = (authHeader) -> authHeader.substring(BEARER_PREFIX.length());

}
