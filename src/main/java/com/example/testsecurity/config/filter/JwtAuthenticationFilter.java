package com.example.testsecurity.config.filter;

import com.example.testsecurity.config.JwtUtils;
import com.example.testsecurity.entity.BlackListRefreshTokenEntity;
import com.example.testsecurity.service.TaskDeleteRefreshTokenService;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import static com.example.testsecurity.config.JwtUtils.SecretEnum.REFRESH_SECRET;
import static com.example.testsecurity.config.JwtUtils.isTokenCorrectType;
import static com.example.testsecurity.utils.SecurityUtils.BEARER_PREFIX;
import static com.example.testsecurity.utils.SecurityUtils.GET_BEARER_TOKEN;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    UserDetailsService userDetailsService;
    TaskDeleteRefreshTokenService taskDeleteRefreshTokenService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String token = GET_BEARER_TOKEN.apply(authHeader);

            if (isTokenCorrectType(token, REFRESH_SECRET)) {
                if (taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
                    log.warn("Custom Filter: Refresh token already in blacklist");
                    return;
                } else {
                    BlackListRefreshTokenEntity blackListRefreshTokenEntity = new BlackListRefreshTokenEntity();
                    blackListRefreshTokenEntity.setRefreshToken(token);

                    Date expirationDate = JwtUtils.extractExpiration(token);
                    expirationDate = expirationDate == null ? new Date() : expirationDate;
                    ZonedDateTime expiration = expirationDate.toInstant().atZone(ZoneId.systemDefault());
                    blackListRefreshTokenEntity.setExpiration(expiration);

                    taskDeleteRefreshTokenService.addToBlackListAndAndCreateTask(blackListRefreshTokenEntity);
                    log.info("Custom Filter: Refresh token added in blacklist and create task");
                }

            }

            String username = JwtUtils.extractUserName(token);
            if (username != null) {
                try {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    SecurityContext context = SecurityContextHolder.getContext();
                    if (context.getAuthentication() == null) {

                        if (JwtUtils.isTokenValid(token, userDetails)) {
                            Authentication authentication = UsernamePasswordAuthenticationToken
                                    .authenticated(userDetails, null, userDetails.getAuthorities());
                            context.setAuthentication(authentication);
                        } else log.warn("Custom Filter: Invalid token");

                    } else log.warn("Custom Filter: User has be authenticated");

                } catch (UsernameNotFoundException exception) {
                    log.warn("Custom Filter: Invalid username in token");
                }
            } else log.debug("Custom Filter: Token expired or other");

        } else log.debug("Custom Filter: Invalid authHeader");

        filterChain.doFilter(request, response);

    }
}
