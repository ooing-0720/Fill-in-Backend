package com.fillin.domain.user.domain;

import com.fillin.global.common.Role;
import com.fillin.global.common.SocialType;
import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "USERS")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "user_id")
    private Long id;

    @Column(unique = true)
    private String email;
    private String nickname;
    private LocalDateTime createDay;

    @Nullable
    private LocalDateTime modifyDay;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialType socialType;      // NAVER, KAKAO, GOOGLE

    @Column(unique = true)
    private String socialId;

    @Nullable
    private String refreshToken;

    public void authorizeUser() {
        this.role = Role.USER;
    }

    public void updateRefreshToken(String updateRefreshToken) {
        this.refreshToken = updateRefreshToken;
    }
}
