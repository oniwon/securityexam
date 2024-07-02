package org.example.securityexam3;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    // 계정이 user 하나만 존재 -- 계정 추가
    // 인증만 되면 어떤 페이지든 갈 수 있음 -- 권한 추가

    @GetMapping("/info")
    public String info(){
        return "info";
    }

    @GetMapping("/hi")
    public String hi(){
        return "hi";
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm Page";
    }

    @GetMapping("/success")
    public String success(){
        return "success";
    }

    @GetMapping("/fail")
    public String fail(){
        return "fail";
    }

    @GetMapping("/test")
    public String test(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // ContextHolder 이용, 현재 스레드의 보안 컨텍스트에서 인증 정보를 가져옴
        System.out.println(authentication.isAuthenticated());
        if(authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal() instanceof String) {
            return "익명사용자입니다.";
        }

        // 로그인 인증 후
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return "Username ::" + userDetails.getUsername();
    }
}
