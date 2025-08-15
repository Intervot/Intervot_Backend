package com.intervot.intervot.domain.auth.dto;

import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
public class RefreshRequest {
    @NotBlank(message = "Refresh Token은 필수입니다.")
    private String refreshToken;
}