package com.example.testsecurity.service;

import com.example.testsecurity.dto.SignRequestDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface SecurityService {
    ResponseEntity<?> signUp(SignRequestDto signRequestDto);
    ResponseEntity<?> allowSignInUser(String username, String token);
    ResponseEntity<?> signIn(SignRequestDto signRequestDto);
    ResponseEntity<?> logout(Authentication authentication, String token);
    ResponseEntity<?> refreshAccessToken(Authentication authentication, String token);
    ResponseEntity<?> refreshTokens(Authentication authentication, String token);
    ResponseEntity<?> grantAdministratorRights(SignRequestDto signRequestDto, String token);
    ResponseEntity<?> getListUserEntity(String token);
}
