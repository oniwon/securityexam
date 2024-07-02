package org.example.securityexam;

import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeRequests(authorizeRequest -> authorizeRequest
                        .anyRequest() // 모든 요청
                        .authenticated() // 인증을 요구
                );
//                .formLogin(Customizer.withDefaults());

        http
                .formLogin(formLogin -> formLogin
//                        .loginPage("/loginForm") // 시큐리티 기본으로 제공하는 페이지가 아니라, 사용자가 원하는 로그인페이지로 이동하게
                        .defaultSuccessUrl("/success")
                        .failureUrl("/fail")
                                .successHandler((request, response, authentication) -> {
                                    log.info("authentication :: " + authentication.getName());
                                    response.sendRedirect("/success");
                                })
                                .failureHandler((request, response, exception) -> {
                                    log.info("exception :: " + exception.getMessage());
                                    response.sendRedirect("/login");
                                })
//                        .usernameParameter("userId")
//                        .passwordParameter("passwd")
//                        .loginProcessingUrl("/login_p")
                        .permitAll() //loginPage 에 대한 요청은 누구나 요청할 수 있도록
                );
        http
                .logout(logout -> logout
//                        .logoutUrl("/log_out")
                        .logoutSuccessUrl("/login")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            log.info("addLogoutHandler ");
                            HttpSession session = request.getSession();
                            session.invalidate();
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            log.info("logoutSuccessHandler ");
                            response.sendRedirect("/logout");
                        })
                        .deleteCookies("remember-me")
                );


        return http.build();
    }

}
