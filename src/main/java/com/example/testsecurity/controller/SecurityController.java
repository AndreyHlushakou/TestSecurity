package com.example.testsecurity.controller;

import com.example.testsecurity.dto.SignRequestDto;
import com.example.testsecurity.service.SecurityService;
import jakarta.annotation.security.RolesAllowed;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import static com.example.testsecurity.utils.SecurityUtils.GET_BEARER_TOKEN;
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

    @PostMapping("/allowSignInUser")
//    @Secured("ROLE_ADMIN")
//    @RolesAllowed("ROLE_ADMIN")
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity<?> allowSignInUser(@RequestBody String username) {
        return securityService.allowSignInUser(username);
    }

    @PostMapping("/signIn")
    public ResponseEntity<?> signIn(@RequestBody SignRequestDto signRequestDto) {
        return securityService.signIn(signRequestDto);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(AUTHORIZATION) String authHeader,
                                    Authentication authentication) {
        return securityService.logout(authentication, authHeader);
    }

    @GetMapping("/refreshAccessToken")
    public ResponseEntity<?> refreshAccessToken(@RequestHeader(AUTHORIZATION) String authHeader,
                                                Authentication authentication) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.refreshAccessToken(authentication, token);
    }

    @GetMapping("/refreshTokens")
    public ResponseEntity<?> refreshTokens(@RequestHeader(AUTHORIZATION) String authHeader,
                                           Authentication authentication) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.refreshTokens(authentication, token);
    }

    @GetMapping("/grantAdministratorRights")
//    @Secured("ROLE_ADMIN")
    public ResponseEntity<?> grantAdministratorRights(@RequestHeader(AUTHORIZATION) String authHeader,
                                                      @RequestBody SignRequestDto signRequestDto) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.grantAdministratorRights(signRequestDto, token);
    }

    @GetMapping("/getListUserEntity")
    @Secured("ROLE_ADMIN")
    public ResponseEntity<?> getListUserEntity(@RequestHeader(AUTHORIZATION) String authHeader) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.getListUserEntity(token);
    }

}
