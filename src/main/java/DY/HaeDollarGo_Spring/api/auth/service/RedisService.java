package DY.HaeDollarGo_Spring.api.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate redisTemplate;


    public String getValue(String token,String opt) {
        String key = opt + "_" + token;
        Object value = redisTemplate.opsForValue().get(key);
        return value != null ? value.toString() : null;
    }

    @Transactional
    public void saveValue(String token, String opt, Long ttl) {
        String key = opt + "_" + token;
        log.info("kekekekeke");
        redisTemplate.opsForValue().set(key, opt, ttl, TimeUnit.MICROSECONDS);

    }

    public void updateValue(String token, String opt, Long ttl) {
        String key = opt + "_" + token;
        redisTemplate.opsForValue().set(key, opt, ttl, TimeUnit.MICROSECONDS);
    }

    public void deleteValue(String token, String opt) {
        String key = opt + "_" + token;
        redisTemplate.delete(key);
    }
}
