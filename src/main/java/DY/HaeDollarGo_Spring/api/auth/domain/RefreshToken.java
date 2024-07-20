package DY.HaeDollarGo_Spring.api.auth.domain;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Getter
@RedisHash("jwt")
@AllArgsConstructor
public class RefreshToken {

    @Id
    private String token;

    @TimeToLive
    private Long ttl;

    public void update(Long ttl) {
        this.ttl = ttl;
    }

    public RefreshToken updateRefreshToken(String token,Long ttl) {
        this.token = token;
        this.ttl = ttl;
        return this;
    }
}
