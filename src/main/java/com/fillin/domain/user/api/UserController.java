package com.fillin.domain.user.api;


import com.fillin.global.user.CustomUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login/oauth2/code")
public class UserController {

    @GetMapping("/login-test")
    public ResponseEntity<?> naverOauthRedirect(@AuthenticationPrincipal CustomUserDetails userDetails) {
        return ResponseEntity.ok().body(userDetails.getEmail());
    }

}
