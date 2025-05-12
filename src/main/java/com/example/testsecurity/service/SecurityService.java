package com.example.testsecurity.service;

import com.example.testsecurity.dto.SignRequestDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface SecurityService {
    ResponseEntity<?> signUp(SignRequestDto signRequestDto);
    ResponseEntity<?> signIn(SignRequestDto signRequestDto);
    ResponseEntity<?> logout(String token);
    ResponseEntity<?> refreshTokens(Authentication authentication, String token);

    ResponseEntity<?> lockUser(String username);
    ResponseEntity<?> unlockUser(String username);
    ResponseEntity<?> grantAdministratorRights(String username);
    ResponseEntity<?> revokeAdministratorRights(String username);
}
