package com.fillin.global.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fillin.domain.user.dao.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
public class JwtService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private String accessExpiration;

    @Value("${jwt.refresh.expiration}")
    private String refreshExpiration;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String BEARER = "Bearer";

    private final UserRepository userRepository;

    // access token 발급
    public String createAccessToken(String email) {
        log.info("createAccessToken");
        Date now = new Date();
        log.info(String.valueOf(now.getTime() + accessExpiration));
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + Long.parseLong(accessExpiration)))
                .withClaim(EMAIL_CLAIM, email)
                .sign(Algorithm.HMAC512(secretKey));
    }

    // refresh token 발급
    public String createRefreshToken() {
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + Long.parseLong(refreshExpiration)))
                .sign(Algorithm.HMAC512(secretKey));
    }

    // access token 헤더에 보내기
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
        log.info("재발급된 Access Token : {}", accessToken);
    }

    // (로그인시) access token + refresh token 헤더에 보내기
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
        response.setHeader(refreshHeader, refreshToken);
        log.info(String.valueOf(response));
        log.info("Acess, Refresh Token 설정 완료");
    }

    // refresh token 추출(BEARER 제외 순수 토큰만)
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        log.info("extractRefreshToken");

        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    // access token 추출(BEARER 제외 순수 토큰만)
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        log.info("extractAccessToken");

        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }

    // access token에서 email 추출
    public Optional<String> extractEmail(String accessToken) {
        try {
            log.info("extractEmail");

            // token 유효성 검사
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
                    .build()
                    .verify(accessToken)
                    .getClaim(EMAIL_CLAIM)
                    .asString());
        } catch (Exception e) {
            log.info("유효하지 않은 access token");
            return Optional.empty();
        }
    }

    // refresh token DB 저장/업데이트
    public void updateRefreshToken(String email, String refreshToken) {
        log.info("update Refresh Token");
        userRepository.findByEmail(email)
                .ifPresentOrElse(user ->
                        {
                            log.info(refreshToken);
                            user.updateRefreshToken(refreshToken);
                            userRepository.saveAndFlush(user);
                        },
                        () -> log.info("회원 없음")
                );
    }

    // 토큰 유효성 검사
    public boolean isTokenValid(String token) {
        log.info("isTokenValid");
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 토큰, {}", e.getMessage());
            return false;
        }
    }
}
