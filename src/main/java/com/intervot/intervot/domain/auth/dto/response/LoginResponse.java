package com.intervot.intervot.domain.auth.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
    private long accessTokenExpiresAt;
    private String accessToken;
    private String refreshToken;
    private String nickname;
}