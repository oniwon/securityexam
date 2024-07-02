package org.example.securityexam3;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/shop")
public class ShopController {

    @GetMapping("/list")
    public String list() {
        return "item list";
    }

    @GetMapping("/item")
    public String item() {
        return "item details";
    }

}
