package com.intervot.intervot.domain.auth.controller;

import com.intervot.intervot.domain.auth.dto.request.LoginRequest;
import com.intervot.intervot.domain.auth.dto.request.RefreshRequest;
import com.intervot.intervot.domain.auth.dto.request.SignupRequest;
import com.intervot.intervot.domain.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RedisTemplate<String, String> redisTemplate;
    private final AuthService authService;

    @GetMapping("/ping")
    public String ping() {
        return "AuthController is working!";
    }

    // Redis 테스트용 엔드포인트
    @GetMapping("/redis-test")
    public String redisTest() {
        String key = "test-key";
        String value = "Hello Redis!";

        // Redis에 저장
        redisTemplate.opsForValue().set(key, value);

        // Redis에서 조회
        String redisValue = redisTemplate.opsForValue().get(key);

        return "Redis returned: " + redisValue;
    }

    // 로그인 API
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("============로그인 API 진입=================");
        return authService.login(loginRequest.getEmail(), loginRequest.getPassword());
    }

    // 회원가입 API
    @PostMapping("/signup")
    public ResponseEntity<Map<String, Object>> signup(@Valid @RequestBody SignupRequest signupRequest) {
        log.info("============회원가입 API 진입=================");
        return authService.signup(signupRequest.getEmail(), signupRequest.getPassword(), signupRequest.getNickname());
    }

    // Access Token 재발급 API
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(
            @RequestHeader("Authorization") String accessToken,
            @Valid @RequestBody RefreshRequest refreshRequest) {
        log.info("============토큰 재발급 API 진입=================");
        return authService.refreshAccessToken(accessToken, refreshRequest.getRefreshToken());
    }

    // 로그아웃 API
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@RequestHeader("Authorization") String authHeader) {
        log.info("============로그아웃 API 진입=================");
        return authService.logout(authHeader);
    }

    // 토큰 검증 API (테스트용)
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestHeader("Authorization") String authHeader) {
        log.info("============토큰 검증 API 진입=================");
        return authService.validateToken(authHeader);
    }
}