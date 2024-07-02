package org.example.zizonsecurity.config;

import lombok.RequiredArgsConstructor;
import org.example.zizonsecurity.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/userregform", "/userreg", "/").permitAll()
                        .anyRequest().authenticated()
                )

//                .formLogin(Customizer.withDefaults())

                // 폼 로그인 설정
                .formLogin(form -> form
                        .loginPage("/loginform")
                        .loginProcessingUrl("/login") // 로그인 폼의 action URL
                        /*
                        작동 순서:
                        사용자가 로그인 폼에서 입력한 사용자 이름과 비밀번호를 제출할 때,
                        이 URL("/login")로 POST 요청이 전송됨.
                        Spring Security는 이 URL로 들어오는 요청을 가로채고,
                        사용자 인증을 처리
                        =>  controller 에 @PostMapping 을 하지 않아도 됨!
                         */
                        .defaultSuccessUrl("/welcome") // 로그인 성공 시 리다이렉트할 경로 설정
                        .permitAll() // 로그인 페이지에 다 접근 가능
                )

                // 로그아웃 설정
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                )

                // 세션 관리 설정
                .sessionManagement(sessionManagement -> sessionManagement // 동시 잡속 허용자 수 설정
                                .maximumSessions(1)
                                .maxSessionsPreventsLogin(true) // 동시 로그인 차단
                        // default=false => 먼저 로그인한 사용자 차단
                        // true => 허용 세션 수 초과하는 사용자 차단
                )


                .userDetailsService(customUserDetailsService) // security 에게 알려주기
                .csrf(csrf -> csrf.disable());


        return http.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
