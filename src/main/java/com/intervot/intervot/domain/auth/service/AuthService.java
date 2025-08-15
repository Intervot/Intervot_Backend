package com.intervot.intervot.domain.auth.service;

import com.intervot.intervot.domain.auth.entity.User;
import com.intervot.intervot.domain.auth.repository.AuthRepository;
import com.intervot.intervot.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthRepository authRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    // 로그인
    public ResponseEntity<Map<String, Object>> login(String email, String password) {
        Map<String, Object> responseMap = new HashMap<>();

        try {
            log.info("로그인 시도 - 이메일: {}", email);

            // 사용자 조회 (이메일로만 조회)
            Optional<User> userOptional = authRepository.findByEmail(email);

            if (userOptional.isEmpty()) {
                log.warn("사용자를 찾을 수 없습니다: {}", email);
                responseMap.put("message", "이메일 또는 비밀번호가 올바르지 않습니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            User user = userOptional.get();
            log.info("사용자 찾음 - ID: {}, 이메일: {}, 닉네임: {}", user.getId(), user.getEmail(), user.getNickname());

            // 비밀번호 검증
            boolean passwordMatches = passwordEncoder.matches(password, user.getPassword());
            log.info("비밀번호 일치 여부: {}", passwordMatches);

            if (!passwordMatches) {
                log.warn("비밀번호가 일치하지 않습니다: {}", email);
                responseMap.put("message", "이메일 또는 비밀번호가 올바르지 않습니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            // JWT 토큰 생성 (일관성을 위해 JwtUtil 사용)
            String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getNickname());
            String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

            // Refresh Token을 Redis에 저장 (이메일 기반으로 저장)
            redisTemplate.opsForValue().set(
                    "RT:" + user.getEmail(),
                    refreshToken,
                    Duration.ofDays(7) // 7일 만료
            );

            // 활성 세션 저장
            saveActiveSession(user.getEmail(), accessToken);

            // Access Token 만료 시간
            long accessTokenExpiresAt = jwtUtil.getAccessTokenExpiresAt();

            // 응답 데이터 구성
            responseMap.put("accessToken", accessToken);
            responseMap.put("refreshToken", refreshToken);
            responseMap.put("accessTokenExpiresAt", accessTokenExpiresAt);
            responseMap.put("nickname", user.getNickname());
            responseMap.put("message", "로그인 성공");

            log.info("로그인 성공: {}", email);
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);

        } catch (Exception e) {
            log.error("로그인 처리 중 오류 발생", e);
            responseMap.put("message", "로그인 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }
    }

    // 회원가입
    public ResponseEntity<Map<String, Object>> signup(String email, String password, String nickname) {
        Map<String, Object> responseMap = new HashMap<>();

        try {
            log.info("회원가입 시도 - 이메일: {}, 닉네임: {}", email, nickname);

            // 이메일 중복 체크
            if (authRepository.existsByEmail(email)) {
                log.warn("이미 사용 중인 이메일: {}", email);
                responseMap.put("message", "이미 사용 중인 이메일입니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            // 닉네임 중복 체크
            if (authRepository.existsByNickname(nickname)) {
                log.warn("이미 사용 중인 닉네임: {}", nickname);
                responseMap.put("message", "이미 사용 중인 닉네임입니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            // 비밀번호 규칙 재검증 (서버 사이드)
            if (!isValidPassword(password)) {
                log.warn("비밀번호 규칙 위반: {}", email);
                responseMap.put("message", "비밀번호는 대문자, 소문자, 특수문자를 각각 최소 1개씩 포함하고 10자 이상이어야 합니다.");
                responseMap.put("field", "password");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            // 비밀번호 암호화
            String encodedPassword = passwordEncoder.encode(password);
            log.info("비밀번호 암호화 완료");

            // 사용자 생성
            User user = User.builder()
                    .email(email)
                    .password(encodedPassword)
                    .nickname(nickname)
                    .build();

            // 데이터베이스에 저장
            User savedUser = authRepository.save(user);
            log.info("사용자 저장 완료 - ID: {}", savedUser.getId());

            responseMap.put("message", "회원가입이 완료되었습니다.");

            log.info("회원가입 성공: {}", email);
            return ResponseEntity.status(HttpStatus.CREATED).body(responseMap);

        } catch (Exception e) {
            log.error("회원가입 처리 중 오류 발생", e);
            responseMap.put("message", "회원가입 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }
    }

    // Access Token 재발급 (Controller에서 이동)
    public ResponseEntity<Map<String, Object>> refreshAccessToken(String authHeader, String refreshToken) {
        Map<String, Object> responseMap = new HashMap<>();

        try {
            log.info("토큰 재발급 시도");

            // 1. Authorization 헤더에서 Access Token 추출
            String accessToken = extractTokenFromHeader(authHeader);
            if (accessToken == null) {
                responseMap.put("message", "유효하지 않은 Authorization 헤더입니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            // 2. Access Token에서 이메일 추출 (만료되어도 정보는 추출 가능)
            String emailFromAccessToken;
            try {
                emailFromAccessToken = jwtUtil.getEmailFromToken(accessToken);
            } catch (Exception e) {
                log.warn("Access Token에서 이메일 추출 실패");
                responseMap.put("message", "유효하지 않은 Access Token입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
            }

            // 3. Refresh Token 유효성 검증
            if (!jwtUtil.isTokenValid(refreshToken) ||
                    !"refresh".equals(jwtUtil.getTokenType(refreshToken))) {
                log.warn("유효하지 않은 Refresh Token");
                responseMap.put("message", "유효하지 않은 Refresh Token입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
            }

            // 4. Refresh Token에서 이메일 추출
            String emailFromRefreshToken = jwtUtil.getEmailFromToken(refreshToken);

            // 5. Access Token과 Refresh Token의 이메일이 일치하는지 확인
            if (!emailFromAccessToken.equals(emailFromRefreshToken)) {
                log.warn("Access Token과 Refresh Token의 사용자 불일치: {} vs {}",
                        emailFromAccessToken, emailFromRefreshToken);
                responseMap.put("message", "토큰 소유자가 일치하지 않습니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
            }

            // 6. Redis에서 저장된 Refresh Token과 비교
            if (!isValidRefreshToken(emailFromRefreshToken, refreshToken)) {
                log.warn("만료되거나 유효하지 않은 Refresh Token: {}", emailFromRefreshToken);
                responseMap.put("message", "만료되거나 유효하지 않은 Refresh Token입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
            }

            // 7. 사용자 정보 조회
            String nickname = getNicknameByEmail(emailFromRefreshToken);
            if (nickname == null) {
                log.warn("사용자를 찾을 수 없습니다: {}", emailFromRefreshToken);
                responseMap.put("message", "사용자를 찾을 수 없습니다.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseMap);
            }

            // 8. 기존 Access Token을 블랙리스트에 추가 (보안상 좋은 조치)
            addToBlacklist(accessToken);

            // 9. 새로운 Access Token 생성
            String newAccessToken = jwtUtil.generateAccessToken(emailFromRefreshToken, nickname);
            long accessTokenExpiresAt = jwtUtil.getAccessTokenExpiresAt();

            // 10. 새로운 활성 세션 저장
            saveActiveSession(emailFromRefreshToken, newAccessToken);

            // 11. 응답 생성 (Refresh Token은 재발급 안함)
            responseMap.put("accessToken", newAccessToken);
            responseMap.put("accessTokenExpiresAt", accessTokenExpiresAt);
            responseMap.put("message", "토큰 재발급 성공");

            log.info("토큰 재발급 성공: {}", emailFromRefreshToken);
            return ResponseEntity.ok(responseMap);

        } catch (Exception e) {
            log.error("토큰 재발급 중 오류 발생", e);
            responseMap.put("message", "토큰 재발급 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }
    }

    // 로그아웃 (Controller에서 이동)
    public ResponseEntity<Map<String, Object>> logout(String authHeader) {
        Map<String, Object> responseMap = new HashMap<>();

        try {
            log.info("로그아웃 시도");

            // Bearer 토큰에서 JWT 추출
            String token = extractTokenFromHeader(authHeader);
            if (token == null) {
                responseMap.put("message", "유효하지 않은 Authorization 헤더입니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            String email = jwtUtil.getEmailFromToken(token);

            // 1. Access Token을 블랙리스트에 추가
            addToBlacklist(token);

            // 2. Redis에서 Refresh Token 삭제
            deleteRefreshToken(email);

            responseMap.put("message", "로그아웃 성공");

            log.info("로그아웃 성공: {}", email);
            return ResponseEntity.ok(responseMap);

        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류 발생", e);
            responseMap.put("message", "로그아웃 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }
    }

    // 토큰 검증 (Controller에서 이동)
    public ResponseEntity<Map<String, Object>> validateToken(String authHeader) {
        Map<String, Object> responseMap = new HashMap<>();

        try {
            log.info("토큰 검증 시도");

            String token = extractTokenFromHeader(authHeader);
            if (token == null) {
                responseMap.put("message", "유효하지 않은 Authorization 헤더입니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMap);
            }

            // 1. 블랙리스트 확인
            if (isTokenBlacklisted(token)) {
                log.warn("블랙리스트에 등록된 토큰");
                responseMap.put("message", "블랙리스트에 등록된 토큰입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
            }

            // 2. JWT 토큰 유효성 검증
            if (jwtUtil.isTokenValid(token)) {
                String email = jwtUtil.getEmailFromToken(token);
                String nickname = jwtUtil.getNicknameFromToken(token);

                responseMap.put("message", "토큰 유효");
                responseMap.put("email", email);
                responseMap.put("nickname", nickname);

                log.info("토큰 검증 성공: {}", email);
                return ResponseEntity.ok(responseMap);
            }

            responseMap.put("message", "유효하지 않은 토큰");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);

        } catch (Exception e) {
            log.error("토큰 검증 실패", e);
            responseMap.put("message", "토큰 검증 실패");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
        }
    }

    // 기존 메서드들
    private boolean isValidPassword(String password) {
        if (password == null || password.length() < 10) {
            return false;
        }

        boolean hasLowerCase = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpperCase = password.chars().anyMatch(Character::isUpperCase);
        boolean hasSpecialChar = password.chars().anyMatch(ch ->
                "!@#$%^&*(),.?\":{}|<>".indexOf(ch) >= 0
        );

        return hasLowerCase && hasUpperCase && hasSpecialChar;
    }

    public boolean isValidRefreshToken(String email, String refreshToken) {
        try {
            // 이메일을 직접 키로 사용하여 Redis에서 조회
            String storedRefreshToken = redisTemplate.opsForValue().get("RT:" + email);
            boolean isValid = storedRefreshToken != null && storedRefreshToken.equals(refreshToken);

            log.info("Refresh Token 검증 - 이메일: {}, 저장된 토큰 존재: {}, 토큰 일치: {}",
                    email, storedRefreshToken != null, isValid);

            return isValid;
        } catch (Exception e) {
            log.error("Refresh Token 검증 중 오류 발생", e);
            return false;
        }
    }

    public String getNicknameByEmail(String email) {
        Optional<User> userOptional = authRepository.findByEmail(email);
        return userOptional.map(User::getNickname).orElse(null);
    }

    public void saveActiveSession(String email, String accessToken) {
        try {
            long expirationTime = jwtUtil.getAccessTokenExpiresAt();
            long remainingTime = expirationTime - System.currentTimeMillis();

            if (remainingTime > 0) {
                redisTemplate.opsForValue().set(
                        "AS:" + email,
                        accessToken,
                        Duration.ofMillis(remainingTime)
                );
                log.info("활성 세션 저장 완료: {}", email);
            }
        } catch (Exception e) {
            log.error("활성 세션 저장 중 오류 발생", e);
        }
    }

    public void addToBlacklist(String token) {
        try {
            long expirationTime = jwtUtil.getExpirationFromToken(token);
            long remainingTime = expirationTime - System.currentTimeMillis();

            if (remainingTime > 0) {
                redisTemplate.opsForValue().set(
                        "BL:" + token,
                        "true",
                        Duration.ofMillis(remainingTime)
                );
                log.info("토큰 블랙리스트 추가 완료");
            }
        } catch (Exception e) {
            log.error("토큰 블랙리스트 추가 중 오류 발생", e);
        }
    }

    public void deleteRefreshToken(String email) {
        try {
            // 이메일을 직접 키로 사용하여 Redis에서 삭제
            redisTemplate.delete("RT:" + email);
            redisTemplate.delete("AS:" + email); // 활성 세션도 함께 삭제
            log.info("Refresh Token 삭제 완료: {}", email);
        } catch (Exception e) {
            log.error("Refresh Token 삭제 중 오류 발생", e);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        return redisTemplate.hasKey("BL:" + token);
    }

    // 헬퍼 메서드
    private String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.replace("Bearer ", "");
        }
        return null;
    }
}