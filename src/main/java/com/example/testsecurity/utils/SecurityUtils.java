package com.example.testsecurity.utils;

import com.example.testsecurity.entity.RoleEntity;
import lombok.experimental.FieldDefaults;

import java.util.function.UnaryOperator;

@FieldDefaults(makeFinal = true)
public final class SecurityUtils {

    public static final String ROLE_ADMIN = "ROLE_ADMIN"; //RoleEntity.RoleEnum.ROLE_ADMIN.name();

    public static final String DEFAULT_ADMIN_NAME = "admin";

    public static final String BEARER_PREFIX = "Bearer ";
    public static final UnaryOperator<String> GET_BEARER_TOKEN = (authHeader) -> authHeader.substring(BEARER_PREFIX.length());

}
