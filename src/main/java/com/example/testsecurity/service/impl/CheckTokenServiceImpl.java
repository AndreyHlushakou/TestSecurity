package com.example.testsecurity.service.impl;

import com.example.testsecurity.repository.UserRepository;
import com.example.testsecurity.service.CheckTokenService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CheckTokenServiceImpl implements CheckTokenService {

    UserRepository userRepository;

    @Override
    public String userLogged(Authentication authentication) {
        if (authentication == null) {
            return "You are not logged in";
        }
        return authentication.toString();
    }

}
