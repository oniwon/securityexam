package org.example.jwtexam.jwt.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;

@Component
@Slf4j
public class JwtTokenizer {
    private final byte[] accessSecret;
    private final byte[] refreshSecret;

    // 토큰 만료 시간 설정 -> ms라서 x1000
    public static Long ACCESS_TOKEN_EXPIRE_COUNT = 30 * 60 * 1000L;              // 30분
    public static Long REFRESH_TOKEN_EXPIRE_COUNT = 7 * 24 * 60 * 60 * 1000L;    // 7일

    /*
        생성자(JwtTokenizer)
        생성자에서 @Value 어노테이션을 통해 주입받은 jwt.secretKey와 jwt.refreshKey를
        UTF-8 인코딩된 바이트 배열로 변환하여 accessSecret 와 refreshSecret 필드에 저장한다.
    */
    public JwtTokenizer(@Value("${jwt.secretKey}") String accessSecret, @Value("${jwt.refreshKey}") String refreshSecret){
        this.accessSecret = accessSecret.getBytes(StandardCharsets.UTF_8);
        this.refreshSecret = refreshSecret.getBytes(StandardCharsets.UTF_8);
    }


    /*
        JWT 생성(createToken 메서드)
        createToken 메서드는 사용자 ID, 이메일, 이름, 사용자명, 역할 등을 기반으로 JWT를 생성한다.
        JWT의 Payload(클레임)에는 이 정보들이 포함되며, 토큰은 발급 시각과 만료 시각이 지정된다.
        signWith 메서드를 통해 HMAC-SHA 알고리즘을 사용하여 서명되며, getSigningKey 메서드를 호출하여 해당 알고리즘에 필요한 SecretKey를 생성한다.
    */
    private String createToken(Long id, String email, String name, String username,
                               List<String> roles, Long expire, byte[] secretKey) {

        Claims claims = Jwts.claims().setSubject(email);
        claims.put("username", username);
        claims.put("name", name);
        claims.put("userId", id);
        claims.put("roles", roles);
//        claims.put("expire", expire);
//        claims.put("secretKey", secretKey);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + expire))
                .signWith(getSigningKey(secretKey))
                .compact();
    }

    /*
        AccessToken 및 RefreshToken 생성 메서드
        createAccessToken 메서드와 createRefreshToken 메서드는 각각 AccessToken과 RefreshToken을 생성한다.
        createToken 메서드를 호출하여 JWT를 생성하며, 각 토큰의 만료 시간과 사용할 보안 키를 지정한다.
    */
    // ACCESS Token 생성
    public String createAccessToken(Long id, String email, String name, String username, List<String> roles) {
        return createToken(id, email, name, username, roles, ACCESS_TOKEN_EXPIRE_COUNT, accessSecret);
    }

    // Refresh Token 생성
    public String createRefreshToken(Long id, String email, String name, String username, List<String> roles) {
        return createToken(id, email, name, username, roles, REFRESH_TOKEN_EXPIRE_COUNT, refreshSecret);
    }

    /*
       서명 키 생성 메소드
       getSigningKey 메서드는 주어진 바이트 배열을 기반으로 HMAC-SHA 알고리즘에 사용할 SecretKey를 생성하여 반환한다.
   */
    public static Key getSigningKey(byte[] secretKey) {
        return Keys.hmacShaKeyFor(secretKey);
    }

    // 토큰에서 유저 아이디 얻기
    public Long getUserIdFromToken(String token){
        String[] tokenArr = token.split(" ");
        token = tokenArr[1];
        Claims claims = parseToken(token, accessSecret);
        return Long.valueOf((Integer)claims.get("userId"));
    }

    /*
    토큰 파싱 및 검증
    parseToken, parseAccessToken, parseRefreshToken 메서드는 각각 AccessToken 및 RefreshToken을 파싱하여 클레임(claims)을 추출한다.
    parseToken 메서드 내에서는 Jwts.parserBuilder()를 통해 JWT 파서를 생성하고, setSigningKey 메서드로 검증에 사용할 SecretKey를 설정한다.
   */
    public Claims parseToken(String token, byte[] secretKey){
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(secretKey))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Claims parseAccessToken(String accessToken) {
        return parseToken(accessToken, accessSecret);
    }

    public Claims parseRefreshToken(String refreshToken) {
        return parseToken(refreshToken, refreshSecret);
    }
}

