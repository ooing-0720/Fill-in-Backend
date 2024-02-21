package com.fillin.global.oauth2.handler;

import com.fillin.domain.user.dao.UserRepository;
import com.fillin.global.jwt.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth 로그인 성공");
        try {
            DefaultOAuth2User oAuth2User = (DefaultOAuth2User) authentication.getPrincipal();

            String accessToken = jwtService.createAccessToken(oAuth2User.getName());
            String refreshToken = jwtService.createRefreshToken();
            response.addHeader(jwtService.getAccessHeader(), "Bearer" + accessToken);
            response.addHeader(jwtService.getRefreshHeader(), "Bearer" + refreshToken);

            jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
            jwtService.updateRefreshToken(oAuth2User.getName(), refreshToken);

            response.sendRedirect("/login");
        } catch (Exception e) {
            log.info("오류 발생" + e.getMessage());
            throw e;
        }
    }
}
