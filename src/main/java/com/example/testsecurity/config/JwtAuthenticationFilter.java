package com.example.testsecurity.config;

import com.example.testsecurity.entity.WhiteListRefreshTokenEntity;
import com.example.testsecurity.repository.WhiteListRefreshTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Optional;

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

    WhiteListRefreshTokenRepository whiteListRefreshTokenRepository;
    UserDetailsService userDetailsService;
    AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String token = GET_BEARER_TOKEN.apply(authHeader);

            if (isTokenCorrectType(token, REFRESH_SECRET)) {
                Optional<WhiteListRefreshTokenEntity> optionalWhiteListRefreshTokenEntity = whiteListRefreshTokenRepository.findByRefreshToken(token);
                if (optionalWhiteListRefreshTokenEntity.isPresent()) {
                    WhiteListRefreshTokenEntity whiteListRefreshTokenEntity = optionalWhiteListRefreshTokenEntity.get();

                    ZonedDateTime expiration = whiteListRefreshTokenEntity.getExpiration();
                    ZonedDateTime now = ZonedDateTime.now();
                    if (now.isAfter(expiration)) {
                        whiteListRefreshTokenRepository.deleteByRefreshToken(token);
                        log.warn("Custom Filter: Refresh token is old. Token deleted from DB");
                        response.sendError(HttpStatus.FORBIDDEN.value());
                        return;
                    }

                    //do nothing
                } else {
                    log.warn("Custom Filter: Refresh token not in whitelist");
                    response.sendError(HttpStatus.FORBIDDEN.value());
                    return;
                }

            }

            String username = JwtUtils.extractUserName(token);
            if (username != null) {
                try {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    if (userDetails.isAccountNonLocked()) {
                        SecurityContext context = SecurityContextHolder.getContext();
                        if (context.getAuthentication() == null) {

                            if (JwtUtils.isTokenValid(token, userDetails)) {

                                UsernamePasswordAuthenticationToken authUser = UsernamePasswordAuthenticationToken
                                        .authenticated(userDetails, null, userDetails.getAuthorities());
                                authUser.setDetails(new WebAuthenticationDetails(request));
                                context.setAuthentication(authUser);

                            } else {
                                log.warn("Custom Filter: Invalid token");
                                response.sendError(HttpStatus.FORBIDDEN.value());
                                return;
                            }

                        } else {
                            log.warn("Custom Filter: User has be authenticated");
                            response.sendError(HttpStatus.FORBIDDEN.value());
                            return;
                        }

                    } else {
                        log.warn("Custom Filter: User is locked");
                        response.sendError(HttpStatus.FORBIDDEN.value());
                        return;
                    }

                } catch (UsernameNotFoundException exception) {
                    log.warn("Custom Filter: Invalid username in token");
                    response.sendError(HttpStatus.FORBIDDEN.value());
                    return;
                }
            } else {
                log.debug("Custom Filter: Token expired or other");
                response.sendError(HttpStatus.FORBIDDEN.value());
                return;
            }

        } else log.debug("Custom Filter: Invalid authHeader");

        filterChain.doFilter(request, response);

    }

}
