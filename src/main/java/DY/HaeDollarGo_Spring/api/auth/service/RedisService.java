package DY.HaeDollarGo_Spring.api.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate redisTemplate;


    public String getValue(String token) {
        Object value = redisTemplate.opsForValue().get(token);
        return value != null ? value.toString() : null;
    }

    @Transactional
    public void saveValue(String token, String userKey, Long ttl) {

        redisTemplate.opsForValue().set(token, userKey, ttl, TimeUnit.MICROSECONDS);
    }

    @Transactional
    public void deleteValue(String token) {

        redisTemplate.delete(token);
    }
}
