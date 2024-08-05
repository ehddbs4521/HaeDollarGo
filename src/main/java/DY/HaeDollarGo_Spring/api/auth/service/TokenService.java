package DY.HaeDollarGo_Spring.api.auth.service;

import DY.HaeDollarGo_Spring.global.common.TokenValue;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static DY.HaeDollarGo_Spring.global.common.TokenValue.REFRESH_TTL;

@RequiredArgsConstructor
@Service
public class TokenService {

    public static void setTokenInHeader(HttpServletResponse response, String token) {
        response.setHeader(TokenValue.ACCESS_HEADER, token);
    }

    public static void setTokenInCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(TokenValue.REFRESH_HEADER, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(REFRESH_TTL.intValue());
        response.addCookie(cookie);
    }
}