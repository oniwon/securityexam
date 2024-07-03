package org.example.jwtexam.controller;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.example.jwtexam.domain.RefreshToken;
import org.example.jwtexam.domain.Role;
import org.example.jwtexam.domain.User;
import org.example.jwtexam.dto.UserLoginResponseDto;
import org.example.jwtexam.jwt.util.JwtTokenizer;
import org.example.jwtexam.security.dto.UserLoginDto;
import org.example.jwtexam.service.RefreshTokenService;
import org.example.jwtexam.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class UserApiController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenizer jwtTokenizer;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    // Dto의 유효성검사를 진행
    public ResponseEntity login(@RequestBody @Valid UserLoginDto userLoginDto,
                                BindingResult bindingResult, HttpServletResponse response) {
        // Dto의 유효성 검사에 오류가 있는 경우
        if(bindingResult.hasErrors()) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        // Dto의 유효성 검사에 오류가 없는 경우 -> 사용자 이름으로 유저 조회
        User user = userService.findByUsername(userLoginDto.getUsername());

        // 조회한 유저의 비밀번호와 입력한 비밀번호 일치하지 않은 경우
        if(!passwordEncoder.matches(userLoginDto.getPassword(), user.getPassword())) {
            return new ResponseEntity("비밀번호가 올바르지 않습니다.", HttpStatus.UNAUTHORIZED);
        }

        // 여기까지 return 안 된 경우 db와 정보가 일치한 정보를 입력한 것 -> 인증 성공(토큰 발급 진행)
        // Roles 객체 꺼내 롤의 이름만 리스트로 얻어오기
        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());

        // 토큰 발급
        String accessToken = jwtTokenizer.createAccessToken(user.getId(), user.getEmail(), user.getName(), user.getUsername(), roles);
        String refreshToken = jwtTokenizer.createRefreshToken(user.getId(), user.getEmail(), user.getName(), user.getUsername(), roles);

        // Refresh Token을 DB에 저장
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setValue(refreshToken);
        refreshTokenEntity.setUserId(user.getId());

        refreshTokenService.addRefreshToken(refreshTokenEntity);

        // 응답으로 보낼 값(토큰을 쿠키로 설정)
        UserLoginResponseDto loginResponseDto = UserLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .name(user.getName())
                .build();

        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);    // 쿠키를 HTTP 요청에서만 사용할 수 있게 하여 보안을 강화합니다.
        accessTokenCookie.setPath("/");         // 쿠키의 경로 설정
        accessTokenCookie.setMaxAge(Math.toIntExact(JwtTokenizer.ACCESS_TOKEN_EXPIRE_COUNT / 1000)); // 쿠키의 유지시간의 단위는 초, 토큰의 유지시간의 단위는 밀리초

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(Math.toIntExact(JwtTokenizer.REFRESH_TOKEN_EXPIRE_COUNT / 1000)); // 쿠키의 유지시간의 단위는 초, 토큰의 유지시간의 단위는 밀리초

        // 응답 객체에 쿠키를 추가
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        // 스프링 MVC는 HttpServletResponse 객체(쿠키)와 ResponseEntity 객체를 결합하여 최종 HTTP 응답을 생성하고 클라이언트에게 전송
        return new ResponseEntity(loginResponseDto, HttpStatus.OK);
    }

    @GetMapping("/api/authtest")
    public String authTest() {
        return "authTest";
    }

    @PostMapping("/refreshToken")
    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {
        //할일!!
        //1. 쿠키로부터 refresh Token을 얻어온다.
        String refreshToken = null;
        Cookie[] cookies = request.getCookies();
        if(cookies != null) {
            for(Cookie cookie : cookies) {
                if("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }
        //2-1. 없을때.
        //오류로 응답
        if(refreshToken == null) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        //2-2. 있을때.
        //토큰으로부터 정보를 얻어온다.
        Claims claims = jwtTokenizer.parseRefreshToken(refreshToken);
        Long userId = Long.valueOf((Integer) claims.get("userId"));

        User user = userService.getUser(userId).orElseThrow(() -> new IllegalArgumentException("사용자를 찾지 못했습니다."));

        //3. accessToken 생성.
        List roles = (List) claims.get("roles");

        String accessToken = jwtTokenizer.createAccessToken(userId, user.getEmail(), user.getName(), user.getUsername(), roles);

        //4. 쿠키 생성 response로 보내고,
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(Math.toIntExact(JwtTokenizer.ACCESS_TOKEN_EXPIRE_COUNT / 1000)); // 초 단위로 넘어오니까 밀리로 바꾸기 위해 1000으로 나눔.

        response.addCookie(accessTokenCookie);

        //5. 적절한 응답결과(ResponseEntity)를 생성해서 응답한다.
        UserLoginResponseDto responseDto = UserLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .name(user.getName())
                .userId(user.getId())
                .build();

        return new ResponseEntity(responseDto, HttpStatus.OK);
    }
}
