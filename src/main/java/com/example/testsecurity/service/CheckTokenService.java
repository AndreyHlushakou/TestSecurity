package com.example.testsecurity.service;

import com.example.testsecurity.entity.UserEntity;
import org.springframework.security.core.Authentication;

import java.util.List;

public interface CheckTokenService {
    String userLogged(Authentication authentication);
    List<UserEntity> getAllUsers();
}
