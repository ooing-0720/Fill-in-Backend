package com.fillin.global.oauth2;

import com.fillin.domain.user.domain.User;
import com.fillin.global.common.Role;
import com.fillin.global.common.SocialType;
import com.fillin.global.oauth2.userinfo.KakaoOAuth2UserInfo;
import com.fillin.global.oauth2.userinfo.NaverOAuth2UserInfo;
import com.fillin.global.oauth2.userinfo.OAuth2UserInfo;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@Slf4j
public class OAuthAttributes {

    private String nameAttributeKey;
    private OAuth2UserInfo oAuth2UserInfo;

    @Builder
    private OAuthAttributes(String nameAttributeKey, OAuth2UserInfo oAuth2UserInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oAuth2UserInfo = oAuth2UserInfo;
    }

    // social type에 맞는 메소드를 호출하여 OAuthAttributes 객체 반환
    public static OAuthAttributes of(SocialType socialType, String userNameAttributeName, Map<String, Object> attributes) {
        log.info("of");
        if (socialType == SocialType.NAVER) {
            return ofNaver(userNameAttributeName, attributes);
        } else if (socialType == SocialType.KAKAO) {
            return ofKakao(userNameAttributeName, attributes);
        }
        return ofNaver(userNameAttributeName, attributes);
    }

    private static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new NaverOAuth2UserInfo(attributes))
                .build();
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new KakaoOAuth2UserInfo(attributes))
                .build();
    }

    public User toEntity(SocialType socialType, OAuth2UserInfo oAuth2UserInfo) {
        return User.builder()
                .socialType(socialType)
                .socialId(oAuth2UserInfo.getId())
                .email(oAuth2UserInfo.getEmail())
                .nickname(oAuth2UserInfo.getNickname())
                .role(Role.USER)
                .createDay(LocalDateTime.now())
                .modifyDay(null)
                .build();
    }

}
