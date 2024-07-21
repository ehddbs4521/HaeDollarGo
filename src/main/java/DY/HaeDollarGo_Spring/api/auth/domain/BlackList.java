package DY.HaeDollarGo_Spring.api.auth.domain;

import org.springframework.data.annotation.Id;
import lombok.Builder;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Getter
@RedisHash("blacklist")
public class BlackList {

    @Id
    private String token;

    @TimeToLive
    private Long ttl;

    @Builder
    public BlackList(String token, Long ttl) {
        this.token = token;
        this.ttl = ttl;
    }

    void update(Long ttl) {
        this.ttl = ttl;
    }
}