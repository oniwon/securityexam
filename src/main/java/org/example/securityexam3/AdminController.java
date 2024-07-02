package org.example.securityexam3;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/abc") // Admin 만 접근할 수 있게
    public String abc(){
        return "abc";
    }

    @GetMapping("/def") // Admin 과 superuser 둘다 접근할 수 있게
    public String def(){
        return "def";
    }

    @GetMapping("/list") // Admin 과 superuser 둘다 접근할 수 있게
    public String list(){
        return "list";
    }

    @GetMapping("/add") // Admin 과 superuser 둘다 접근할 수 있게
    public String add(){
        return "add";
    }

}
