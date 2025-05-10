package com.example.testsecurity.service;

import org.springframework.security.core.Authentication;

public interface CheckTokenService {
    String userLogged(Authentication authentication);
}
