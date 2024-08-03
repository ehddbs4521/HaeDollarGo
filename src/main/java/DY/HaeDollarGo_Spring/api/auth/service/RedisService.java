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


    public String getValue(String userKey) {
        Object value = redisTemplate.opsForValue().get(userKey);
        return value != null ? value.toString() : null;
    }

    @Transactional
    public void saveValue(String userKey, String token, Long ttl) {

        redisTemplate.opsForValue().set(userKey, token, ttl, TimeUnit.MICROSECONDS);
    }

    @Transactional
    public void deleteValue(String userKey) {

        redisTemplate.delete(userKey);
    }
}
