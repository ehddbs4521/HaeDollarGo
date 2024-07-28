package DY.HaeDollarGo_Spring.api.auth.service;

import DY.HaeDollarGo_Spring.api.auth.jwt.TokenProvider;
import DY.HaeDollarGo_Spring.global.common.RedisValue;
import DY.HaeDollarGo_Spring.global.common.TokenValue;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static DY.HaeDollarGo_Spring.global.common.RedisValue.BLACKLIST;
import static DY.HaeDollarGo_Spring.global.common.RedisValue.REFRESH;
import static DY.HaeDollarGo_Spring.global.common.TokenValue.ACCESS_TTL;
import static DY.HaeDollarGo_Spring.global.common.TokenValue.REFRESH_TTL;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenProvider tokenProvider;
    private final RedisService redisService;
    private static final String URL = "/auth/success";

    @Transactional
    public void updateToken(String accessToken, String refreshToken) {

        Long accessTokenTTL = tokenProvider.calculateTimeLeft(accessToken);
        Long refreshTokenTTL = tokenProvider.calculateTimeLeft(refreshToken);

        redisService.updateValue(accessToken, BLACKLIST, accessTokenTTL);
        redisService.updateValue(refreshToken, BLACKLIST, refreshTokenTTL);

        redisService.deleteValue(refreshToken, REFRESH);
    }

    public static void setTokenInHeader(HttpServletResponse response, String token) {
        response.setHeader(TokenValue.ACCESS_HEADER, token);
    }

    public static void setTokenInCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(TokenValue.REFRESH_HEADER, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(URL);
        cookie.setMaxAge(REFRESH_TTL.intValue());
        response.addCookie(cookie);
    }
}