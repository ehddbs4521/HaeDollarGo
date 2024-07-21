package DY.HaeDollarGo_Spring.api.auth.service;

import DY.HaeDollarGo_Spring.api.auth.domain.BlackList;
import DY.HaeDollarGo_Spring.api.auth.domain.RefreshToken;
import DY.HaeDollarGo_Spring.api.auth.jwt.TokenProvider;
import DY.HaeDollarGo_Spring.api.auth.repository.BlackListRepository;
import DY.HaeDollarGo_Spring.api.auth.repository.RefreshTokenRepository;
import DY.HaeDollarGo_Spring.global.common.TokenValue;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final BlackListRepository blackListRepository;
    private final TokenProvider tokenProvider;

    private static final String URL = "/auth/success";

    public boolean existsTokenInBlackList(String token) {
        BlackList blackList = blackListRepository.findById(token).orElseGet(null);
        return blackList != null;
    }

    public boolean existsTokenInRefresh(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findById(token).orElseGet(null);
        return refreshToken != null;
    }

    @Transactional
    public void saveOrUpdate(String userKey, String refreshToken) {
        RefreshToken token = refreshTokenRepository.findById(refreshToken)
                .map(o -> o.updateRefreshToken(refreshToken, TokenValue.REFRESH_TTL))
                .orElseGet(() -> new RefreshToken(refreshToken, TokenValue.REFRESH_TTL));
        refreshTokenRepository.save(token);
    }

    @Transactional
    public void updateToken(String accessToken, String refreshToken) {
        BlackList accessTokenInBlackList = BlackList.builder()
                .token(accessToken)
                .ttl(TokenValue.ACCESS_TTL - tokenProvider.getExpiration(accessToken))
                .build();

        BlackList refreshTokenInBlackList = BlackList.builder()
                .token(refreshToken)
                .ttl(TokenValue.REFRESH_TTL - tokenProvider.getExpiration(refreshToken))
                .build();

        blackListRepository.save(accessTokenInBlackList);
        blackListRepository.save(refreshTokenInBlackList);
        refreshTokenRepository.deleteById(refreshToken);
    }

    public static void setTokenInHeader(HttpServletResponse response, String token) {
        response.setHeader(TokenValue.ACCESS_HEADER, token);
    }

    public static void setTokenInCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(TokenValue.REFRESH_HEADER, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(URL);
        cookie.setMaxAge(TokenValue.REFRESH_TTL.intValue());
        response.addCookie(cookie);
    }
}