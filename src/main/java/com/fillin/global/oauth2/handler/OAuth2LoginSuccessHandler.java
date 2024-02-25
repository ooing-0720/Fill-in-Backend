package com.fillin.global.oauth2.handler;

import com.fillin.domain.user.dao.UserRepository;
import com.fillin.domain.user.domain.User;
import com.fillin.global.jwt.service.JwtService;
import com.fillin.global.oauth2.OAuthAttributes;
import com.fillin.global.oauth2.userinfo.GoogleOAuth2UserInfo;
import com.fillin.global.oauth2.userinfo.KakaoOAuth2UserInfo;
import com.fillin.global.oauth2.userinfo.NaverOAuth2UserInfo;
import com.fillin.global.oauth2.userinfo.OAuth2UserInfo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

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
            Map<String, Object> attributes = oAuth2User.getAttributes();
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String clientRegisterId = oauthToken.getAuthorizedClientRegistrationId();
            OAuth2UserInfo oAuth2UserInfo;

            log.info(clientRegisterId);

            if (clientRegisterId.equals("naver")) {
                oAuth2UserInfo = new NaverOAuth2UserInfo(attributes);
            } else if (clientRegisterId.equals("kakao")) {
                oAuth2UserInfo = new KakaoOAuth2UserInfo(attributes);
            } else {
                oAuth2UserInfo = new GoogleOAuth2UserInfo(attributes);
            }

            log.info(oAuth2UserInfo.getEmail());

            String accessToken = jwtService.createAccessToken(oAuth2UserInfo.getEmail());
            String refreshToken = jwtService.createRefreshToken();
            response.addHeader(jwtService.getAccessHeader(), "Bearer" + accessToken);
            response.addHeader(jwtService.getRefreshHeader(), "Bearer" + refreshToken);

            jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
            jwtService.updateRefreshToken(oAuth2UserInfo.getEmail(), refreshToken);

            response.sendRedirect("/");
        } catch (Exception e) {
            log.info("오류 발생" + e.getMessage());
            throw e;
        }
    }
}
