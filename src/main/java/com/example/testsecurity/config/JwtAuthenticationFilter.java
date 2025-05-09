package com.example.testsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.testsecurity.config.JwtUtils.extractUserName;
import static com.example.testsecurity.config.JwtUtils.isTokenValid;
import static com.example.testsecurity.utils.SecurityUtils.BEARER_PREFIX;
import static com.example.testsecurity.utils.SecurityUtils.GET_BEARER_TOKEN;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String jwtToken = GET_BEARER_TOKEN.apply(authHeader) ;
            String username = extractUserName(jwtToken);

            SecurityContext context = SecurityContextHolder.getContext();

            if (username != null && context.getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if (isTokenValid(jwtToken, userDetails)) {
                    Authentication authentication = UsernamePasswordAuthenticationToken
                            .authenticated(userDetails, null, userDetails.getAuthorities());
                    context.setAuthentication(authentication);
                } else log.warn("Invalid token");
            } else log.warn("Invalid username or user has be authenticated");
        } else log.warn("Invalid authHeader");

        filterChain.doFilter(request, response);

    }
}
