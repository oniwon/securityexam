package org.example.securityexam3;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
@RequestMapping("/user")
public class UserController {

//    @GetMapping("/mypage")
//    public String mypage(@AuthenticationPrincipal UserDetails userDetails) {
//        return "username :: " + userDetails.getUsername();
//    }

    @GetMapping("/mypage")
    public String mypage() {
        return "mypage";
    }
}
