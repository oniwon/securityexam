package org.example.securityexam3;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // 보안 필터 체인 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeRequests(authorizeRequest -> authorizeRequest
                        .requestMatchers("/shop/**", "/test").permitAll() // 이때 지정한 페이지는 누구든지 접근 가능
                        .requestMatchers("/user/mypage").hasRole("USER") // user 만 접근 허용 // admin 으로 로그인하면 403 에러

                        // 경로 설정 주의점: 위에 있는 규칙이 더 구체적이게!
                        .requestMatchers("/admin/abc").hasRole("ADMIN") // admin 만 접근 허용
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SUEPRUSER") //admin, superuser 접근 허용

                        .anyRequest() // 나머지 모든 요청
                        .authenticated() // 인증을 요구
                )
                 .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // 사용자 정보를 제공하기: 사용자 정보를 인메모리에 저장
        // 실제 프로젝트에서는 이 부분을 우리 db 에 있는 사용자 정보를 가져오도록 구현해야 함
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("1234"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();

        UserDetails superuser = User.withUsername("superuser")
                .password(passwordEncoder().encode("1234"))
                .roles("SUEPRUSER")
                .build();

        UserDetails hw = User.withUsername("hw")
                .password(passwordEncoder().encode("1234"))
                .roles("ADMIN", "USER") // 두 권한 모두 주기
                .build();

        // 사용자 정보가 인메모리 방식으로 저장됨
        return new InMemoryUserDetailsManager(user, admin, superuser, hw);
    }

}
