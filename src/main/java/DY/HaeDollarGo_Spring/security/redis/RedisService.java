package DY.HaeDollarGo_Spring.security.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public String getValues(String key){
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteValues(String key) {
        redisTemplate.delete(key);
    }

    public void setValuesWithTimeout(String key, String value, long timeoutInMillis) {
        redisTemplate.opsForValue().set(key, value, timeoutInMillis, TimeUnit.MILLISECONDS);
    }
}
