package com.example.testsecurity.config;

import com.example.testsecurity.entity.RoleEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //чтобы работал @Secured
@RequiredArgsConstructor
public class SecurityConfig {

    //    используется для регистрации
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //    нужен чтобы получить доступ к аунтефикации
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return daoAuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        //  csrf надо отключить, т.к используется jwt

        http.csrf(AbstractHttpConfigurer::disable);
        //    для корса надо писать отдельный конфиг. на данный момент позволяет всем с ним взаимодействовать
//        http.cors(cors ->
//                cors.configurationSource(request -> {
//                    CorsConfiguration corsConfiguration = new CorsConfiguration();
//                    corsConfiguration = corsConfiguration.applyPermitDefaultValues();
//                    return corsConfiguration;
//                }));
        http.cors(AbstractHttpConfigurer::disable);

        //   все кто пытается
        http.authorizeHttpRequests(request -> {
            //  зарегаться или авторизоваться - без аунтефикации
            request.requestMatchers(
                    "/secured/signIn",
                    "/secured/signUp"
            ).anonymous();

            //  все кто уже авторизован - проверяем аунтефикацию
            request.requestMatchers(
                    "/secured/logout",
                    "/secured/refreshTokens",

                    "/checkToken/user"
            ).fullyAuthenticated();

            //  только для админа
            request.requestMatchers(
                    "/secured/lockUser",
                    "/secured/unlockUser",
                    "/secured/grantAdministratorRights",
                    "/secured/revokeAdministratorRights",

                    "/checkToken/getListUserEntity"
            )
                    .fullyAuthenticated();
//                    .hasAuthority(RoleEntity.RoleEnum.ROLE_ADMIN.name());

            //  все остальные запросы запрещены
            request.anyRequest().denyAll();

            //  h2-console чтобы работал. второй вариант. лучше вместе первым
//            request.requestMatchers("/h2-console/**").permitAll();
        });

        //  если кто то пытается подключиться выдается 401 ошибка что не авторизован
        http.exceptionHandling(exception ->
                exception.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

        //  STATELESS т.к. используется jwt а не сессии
        http.sessionManagement(sessionManagementCustomizer ->
                sessionManagementCustomizer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //  h2-console чтобы работал. второй вариант. лучше вместе первым
        http.headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        //  используем кастомный фильтр
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    //  h2-console чтобы работал. 1 варик
//    @Bean
//    WebSecurityCustomizer webSecurityCustomizer() {
//        return webSecurity -> {
//            webSecurity.ignoring().requestMatchers("/h2-console/**");
//        };
//    }

}
