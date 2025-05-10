package com.example.testsecurity.controller;

import com.example.testsecurity.dto.SignRequestDto;
import com.example.testsecurity.service.SecurityService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
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

    @PostMapping("/signIn")
    public ResponseEntity<?> signIn(@RequestBody SignRequestDto signRequestDto) {
        return securityService.signIn(signRequestDto);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(AUTHORIZATION) String authHeader,
                                    Authentication authentication) {
        return securityService.logout(authentication, authHeader);
    }

//    @Secured("ROLE_ADMIN")
//    @RolesAllowed("ROLE_ADMIN")
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @PostMapping("/unlockUser")
    public ResponseEntity<?> unlockUser(@RequestBody String username) {
        return securityService.unlockUser(username);
    }

    @PostMapping("/lockUser")
    public ResponseEntity<?> lockUser(@RequestBody String username) {
        return securityService.lockUser(username);
    }

    //    @Secured("ROLE_ADMIN")
    @PostMapping("/grantAdministratorRights")
    public ResponseEntity<?> grantAdministratorRights(@RequestBody String username) {
        return securityService.grantAdministratorRights(username);
    }

//    @GetMapping("/refreshAccessToken")
//    public ResponseEntity<?> refreshAccessToken(@RequestHeader(AUTHORIZATION) String authHeader,
//                                                Authentication authentication) {
//        String token = GET_BEARER_TOKEN.apply(authHeader);
//        return securityService.refreshAccessToken(authentication, token);
//    }

    @GetMapping("/refreshTokens")
    public ResponseEntity<?> refreshTokens(@RequestHeader(AUTHORIZATION) String authHeader,
                                           Authentication authentication) {
        String token = GET_BEARER_TOKEN.apply(authHeader);
        return securityService.refreshTokens(authentication, token);
    }

}
