//package com.example.testsecurity.config.filter;
//
//import com.example.testsecurity.config.JwtUtils;
//import com.example.testsecurity.service.TaskDeleteRefreshTokenService;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.AccessLevel;
//import lombok.NonNull;
//import lombok.RequiredArgsConstructor;
//import lombok.Setter;
//import lombok.experimental.FieldDefaults;
//import lombok.experimental.NonFinal;
//import lombok.extern.slf4j.Slf4j;
//
//import org.springframework.http.HttpStatus;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//import static com.example.testsecurity.config.JwtUtils.isTokenCorrectType;
//import static com.example.testsecurity.utils.SecurityUtils.BEARER_PREFIX;
//import static com.example.testsecurity.utils.SecurityUtils.GET_BEARER_TOKEN;
//import static org.springframework.http.HttpHeaders.AUTHORIZATION;
//
//@Slf4j
//@Component
//@RequiredArgsConstructor
//@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
//@Setter
//public class TypeTokenFilter extends OncePerRequestFilter {
//
//    @NonFinal
//    JwtUtils.SecretEnum secretEnum;
//
//    TaskDeleteRefreshTokenService taskDeleteRefreshTokenService;
//
//    @Override
//    protected void doFilterInternal(@NonNull HttpServletRequest request,
//                                    @NonNull HttpServletResponse response,
//                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
//
//        String authHeader = request.getHeader(AUTHORIZATION);
//        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
//            String token = GET_BEARER_TOKEN.apply(authHeader);
//
//            if (secretEnum == JwtUtils.SecretEnum.REFRESH_SECRET &&
//                    taskDeleteRefreshTokenService.existsByRefreshToken(token)) {
//                response.setStatus(HttpStatus.BAD_REQUEST.value());
//                String text = "Token in blacklist";
//                setResponse(response, text);
//                return;
//            }
//
//            if (!isTokenCorrectType(token, secretEnum)) {
//                String text = "Incorrect token or type token";
//                setResponse(response, text);
//                return;
//            }
//
//        } else {
//            String text = "Missing or invalid Authorization header";
//            setResponse(response, text);
//            return;
//        }
//
//        filterChain.doFilter(request, response);
//
//    }
//
//    private static void setResponse(@NonNull HttpServletResponse response, String text)  throws IOException{
//        response.setStatus(HttpStatus.BAD_REQUEST.value());
//        response.getWriter().write(text);
//    }
//
//}
