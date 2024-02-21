package com.fillin.domain.user.api;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login/oauth2/code")
public class UserController {

    @GetMapping("/naver")
    public String naverOauthRedirect(@RequestParam String code) {
        return "네이버 인증 완료, code : " + code;
    }
}
