package com.intervot.intervot.domain.redis.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/api/redis")
@RequiredArgsConstructor
public class RedisController {

    private final RedisTemplate<String, String> redisTemplate;

    // Redis 연결 테스트
    @GetMapping("/test")
    public ResponseEntity<Map<String, Object>> testRedisConnection() {
        Map<String, Object> response = new HashMap<>();

        try {
            // 연결 테스트
            redisTemplate.opsForValue().set("connection-test", "ok", Duration.ofSeconds(10));
            String testResult = redisTemplate.opsForValue().get("connection-test");

            response.put("redisConnected", "ok".equals(testResult));
            response.put("message", "Redis 연결 테스트 완료");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("redisConnected", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    // Redis 상태 확인
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> checkRedisStatus() {
        Map<String, Object> response = new HashMap<>();

        try {
            // 연결 테스트
            redisTemplate.opsForValue().set("status-test", "working", Duration.ofSeconds(5));
            String testResult = redisTemplate.opsForValue().get("status-test");

            // 현재 저장된 키들 확인
            Set<String> allKeys = redisTemplate.keys("*");
            Set<String> refreshTokens = redisTemplate.keys("RT:*");
            Set<String> blacklist = redisTemplate.keys("BL:*");

            response.put("redisConnected", "working".equals(testResult));
            response.put("totalKeys", allKeys != null ? allKeys.size() : 0);
            response.put("allKeys", allKeys);
            response.put("refreshTokens", refreshTokens);
            response.put("blacklistTokens", blacklist);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("redisConnected", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    // 상세 Redis 정보 확인
    @GetMapping("/detail")
    public ResponseEntity<Map<String, Object>> checkRedisDetail() {
        Map<String, Object> response = new HashMap<>();

        try {
            // 1. 연결 테스트
            redisTemplate.opsForValue().set("detail-test", "detailed-working", Duration.ofSeconds(10));
            String testValue = redisTemplate.opsForValue().get("detail-test");

            // 2. 모든 키 확인
            Set<String> allKeys = redisTemplate.keys("*");

            // 3. RT: 패턴 키 확인
            Set<String> rtKeys = redisTemplate.keys("RT:*");

            // 4. BL: 패턴 키 확인
            Set<String> blKeys = redisTemplate.keys("BL:*");

            // 5. 각 RT 키의 실제 값과 TTL 확인
            Map<String, Object> rtDetails = new HashMap<>();
            if (rtKeys != null) {
                for (String key : rtKeys) {
                    String value = redisTemplate.opsForValue().get(key);
                    Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                    Boolean exists = redisTemplate.hasKey(key);

                    Map<String, Object> keyInfo = new HashMap<>();
                    keyInfo.put("value", value != null ? value.substring(0, Math.min(50, value.length())) + "..." : "null");
                    keyInfo.put("ttl", ttl + "초");
                    keyInfo.put("exists", exists);

                    rtDetails.put(key, keyInfo);
                }
            }

            // 6. 각 BL 키의 정보 확인
            Map<String, Object> blDetails = new HashMap<>();
            if (blKeys != null) {
                for (String key : blKeys) {
                    String value = redisTemplate.opsForValue().get(key);
                    Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                    Boolean exists = redisTemplate.hasKey(key);

                    Map<String, Object> keyInfo = new HashMap<>();
                    keyInfo.put("value", value);
                    keyInfo.put("ttl", ttl + "초");
                    keyInfo.put("exists", exists);

                    blDetails.put(key, keyInfo);
                }
            }

            response.put("redisConnected", "detailed-working".equals(testValue));
            response.put("allKeysCount", allKeys != null ? allKeys.size() : 0);
            response.put("allKeysList", allKeys);
            response.put("rtKeysCount", rtKeys != null ? rtKeys.size() : 0);
            response.put("rtKeysList", rtKeys);
            response.put("rtDetails", rtDetails);
            response.put("blKeysCount", blKeys != null ? blKeys.size() : 0);
            response.put("blKeysList", blKeys);
            response.put("blDetails", blDetails);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", e.getMessage());
            log.error("Redis 상세 확인 중 오류 발생", e);
            return ResponseEntity.status(500).body(response);
        }
    }

    // 특정 키 확인
    @GetMapping("/key/{keyName}")
    public ResponseEntity<Map<String, Object>> checkSpecificKey(@PathVariable String keyName) {
        Map<String, Object> response = new HashMap<>();

        try {
            Boolean exists = redisTemplate.hasKey(keyName);
            String value = redisTemplate.opsForValue().get(keyName);
            Long ttl = redisTemplate.getExpire(keyName, TimeUnit.SECONDS);

            response.put("key", keyName);
            response.put("exists", exists);
            response.put("value", value);
            response.put("ttl", ttl + "초");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    // Redis 데이터 정리 (개발용)
    @GetMapping("/clear")
    public ResponseEntity<Map<String, Object>> clearRedisData() {
        Map<String, Object> response = new HashMap<>();

        try {
            Set<String> allKeys = redisTemplate.keys("*");
            int deletedCount = 0;

            if (allKeys != null) {
                for (String key : allKeys) {
                    if (redisTemplate.delete(key)) {
                        deletedCount++;
                    }
                }
            }

            response.put("message", "Redis 데이터 정리 완료");
            response.put("deletedKeys", deletedCount);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }
}