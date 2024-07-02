package org.example.jwtexam.config;

import lombok.RequiredArgsConstructor;

import org.example.jwtexam.jwt.exception.CustomAuthenticationEntityPoint;
import org.example.jwtexam.jwt.filter.JwtAuthenticationFilter;
import org.example.jwtexam.jwt.util.JwtTokenizer;
import org.example.jwtexam.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private JwtTokenizer jwtTokenizer;
    private final CustomAuthenticationEntityPoint customAuthenticationEntityPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/userregform", "/userreg", "/", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenizer), UsernamePasswordAuthenticationFilter.class)
                // 폼로그인 막기(JWT를 사용한 인증 방식만 허용)
                .formLogin(form -> form.disable()
                )
                // 세션 사용 못하게 막기 -> JWT 사용
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // CSRF 공격은 주로 세션 기반 인증 시스템에서 문제가 되므로 비활성화
                .csrf(csrf -> csrf.disable())
                // HTTP 기본 인증을 사용하지 않고 JWT를 사용하므로 비활성화
                .httpBasic(httpBasic -> httpBasic.disable())
                // 다른 도메인에서 서버에 요청을 할 수 있도록 CORS 설정을 추가 -> api 테스트 가능
                .cors(cors -> cors.configurationSource(configurationSource()))
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(customAuthenticationEntityPoint));
        return http.build();
    }

    public CorsConfigurationSource configurationSource(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // 모든 도메인(*), 헤더(*), 메소드(*)에 대해 허용
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        // 특히 GET, POST, DELETE 메소드를 허용하도록 명시
        config.setAllowedMethods(List.of("GET", "POST", "DELETE"));
        // 설정은 모든 경로(/**)에 적용
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
