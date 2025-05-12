package com.example.testsecurity.controller;

import com.example.testsecurity.dto.SignRequestDto;
import com.example.testsecurity.service.SecurityService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import static com.example.testsecurity.utils.SecurityUtils.GET_BEARER_TOKEN;
import static com.example.testsecurity.utils.SecurityUtils.ROLE_ADMIN_str;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@RequestMapping("/secured")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SecurityController {

    SecurityService securityService;

    @PostMapping("/signUp")
    public ResponseEntity<?> signUp(@RequestBody SignRequestDto signRequestDto) {
        return securityService.signUp(signRequestDto);
    }

    @PostMapping("/signIn")
    public ResponseEntity<?> signIn(@RequestBody SignRequestDto signRequestDto) {
        return securityService.signIn(signRequestDto);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(AUTHORIZATION) String authHeader) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.logout(token);
    }

    @GetMapping("/refreshTokens")
    public ResponseEntity<?> refreshTokens(@RequestHeader(AUTHORIZATION) String authHeader,
                                           Authentication authentication) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.refreshTokens(authentication, token);
    }

    @PreAuthorize("hasAnyAuthority('" + ROLE_ADMIN_str + "')")
    @PatchMapping("/unlockUser")
    public ResponseEntity<?> unlockUser(@RequestBody String username) {
        return securityService.unlockUser(username);
    }

    @PreAuthorize("hasAnyAuthority('" + ROLE_ADMIN_str + "')")
    @PatchMapping("/lockUser")
    public ResponseEntity<?> lockUser(@RequestBody String username) {
        return securityService.lockUser(username);
    }

    @PreAuthorize("hasAnyAuthority('" + ROLE_ADMIN_str + "')")
    @PatchMapping("/grantAdministratorRights")
    public ResponseEntity<?> grantAdministratorRights(@RequestBody String username) {
        return securityService.grantAdministratorRights(username);
    }

    @PreAuthorize("hasAnyAuthority('" + ROLE_ADMIN_str + "')")
    @PatchMapping("/revokeAdministratorRights")
    public ResponseEntity<?> revokeAdministratorRights(@RequestBody String username) {
        return securityService.revokeAdministratorRights(username);
    }

}
