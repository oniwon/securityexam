package org.example.jwtexam;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.example.jwtexam.jwt.util.JwtTokenizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Arrays;

@SpringBootApplication
@Slf4j
public class JwtexamApplication {
    public static void main(String[] args) {
        SpringApplication.run(JwtexamApplication.class,args);
    }

    @Autowired
    JwtTokenizer jwtTokenizer;
    //    @Bean
    public CommandLineRunner run(){
        return args -> {
            // Access Token 생성
            String accessToken =  jwtTokenizer.createAccessToken(
                    1L,"test@test.com","test", "testuser", Arrays.asList("ROLE_USER")
            );

            log.info("AccessToken {}",accessToken);

            // Refresh Token 생성
            String refreshToken = jwtTokenizer.createRefreshToken(
                    1L,"test@test.com","test", "testuser", Arrays.asList("ROLE_USER")
            );

            log.info("RefreshTokem {}",refreshToken);

//            Long id = jwtTokenizer.getUserIdFromToken(accessToken);
//            log.info("id {}",id);

            // AccessToken 파싱
            Claims claims = jwtTokenizer.parseAccessToken(accessToken);
            log.info("Access Token claims {}",claims);
            log.info("userId :: {}",claims.get("userId"));
//
//            Claims refreshTokenClaims = jwtTokenizer.parseRefreshToken(refreshToken);
//            log.info("Refresh Token claims {}",refreshTokenClaims);
        };

    }
}