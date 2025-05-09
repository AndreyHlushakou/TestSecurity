package com.example.testsecurity.controller;

import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.service.CheckTokenService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/checkToken")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CheckTokenController {

    CheckTokenService checkTokenService;

    @GetMapping("/user")
    public String userAccess(Authentication authentication) {
        return checkTokenService.userLogged(authentication);
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/allUsers")
    public List<UserEntity> allUsers() {
        return checkTokenService.getAllUsers();
    }

}
