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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String token = GET_BEARER_TOKEN.apply(authHeader);

            if (isTokenCorrectType(token, REFRESH_SECRET)) {
                Optional<WhiteListRefreshTokenEntity> optionalWhiteListRefreshTokenEntity = whiteListRefreshTokenRepository.findByRefreshToken(token);
                if (optionalWhiteListRefreshTokenEntity.isEmpty()) {
                    log.debug("Custom Filter: Refresh token not in whitelist");
                    constructResponse(response, "Refresh token not in whitelist");
                    return;
                }

                ZonedDateTime expiration = optionalWhiteListRefreshTokenEntity.get().getExpiration();
                ZonedDateTime now = ZonedDateTime.now();
                if (now.isAfter(expiration)) {
                    whiteListRefreshTokenRepository.deleteByRefreshToken(token);

                    // TODO redirect to signIn
                    log.debug("Custom Filter: Refresh token is old. Token deleted from DB");
                    constructResponse(response, "Refresh token is old");
                    return;
                }
            }

            String username = JwtUtils.extractUserName(token);
            if (username == null) {
                log.debug("Custom Filter: Token expired or other");
                constructResponse(response, "Token expired or other");
                return;
            }

            UserDetails userDetails;
            try {
                userDetails = userDetailsService.loadUserByUsername(username);
            } catch (UsernameNotFoundException exception) {
                log.debug("Custom Filter: Invalid username in token");
                constructResponse(response, "Invalid username in token");
                return;
            }

            if (!userDetails.isAccountNonLocked()) {
                log.debug("Custom Filter: User is locked");
                constructResponse(response, "User is locked");
                return;
            }

            SecurityContext context = SecurityContextHolder.getContext();
            if (context.getAuthentication() != null) {
                log.debug("Custom Filter: User has be authenticated");
                constructResponse(response, "User has be authenticated");
                return;
            }

            if (JwtUtils.isTokenValid(token, userDetails)) {

                UsernamePasswordAuthenticationToken authUser = UsernamePasswordAuthenticationToken
                        .authenticated(userDetails, null, userDetails.getAuthorities());
                authUser.setDetails(new WebAuthenticationDetails(request));
                context.setAuthentication(authUser);

            } else {
                log.debug("Custom Filter: Invalid token");
                constructResponse(response, "Invalid token");
                return;
            }


        } else log.debug("Custom Filter: Invalid authHeader");

        filterChain.doFilter(request, response);

    }

    private static void constructResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
//        response.setContentType("application/json");
//        response.getWriter().write("{\"error\": \"" + message +"\"}");
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write(message);
        response.getWriter().flush();
    }

}
