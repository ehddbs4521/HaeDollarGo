package DY.HaeDollarGo_Spring.api.auth.jwt;

import DY.HaeDollarGo_Spring.api.auth.exception.TokenException;
import DY.HaeDollarGo_Spring.global.common.TokenValue;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

import static DY.HaeDollarGo_Spring.api.auth.service.TokenService.setTokenInCookie;
import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.NOT_EXIST_REFRESHTOKEN;
import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.TOKEN_EXPIRED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@RequiredArgsConstructor
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        log.info("yes");
        String accessToken = tokenProvider.resolveTokenInHeader(request);
        log.info("token: {}", accessToken);
        if (tokenProvider.validateToken(accessToken)) {
            log.info("1");
            setAuthentication(accessToken);
        }
        else {
            if (request.getRequestURI().equals("/auth/reissue")) {
                log.info("2");

                String refreshToken = tokenProvider.getRefreshTokenInCookie(request);
                String reissueAccessToken = tokenProvider.reissueAccessToken(refreshToken);
                if (StringUtils.hasText(reissueAccessToken)) {
                    log.info("3");

                    setAuthentication(reissueAccessToken);
                    response.setHeader(AUTHORIZATION, TokenValue.TOKEN_PREFIX + reissueAccessToken);
                }
                else {
                    log.info("4");

                    throw new TokenException(NOT_EXIST_REFRESHTOKEN);
                }
                if (tokenProvider.isRotateToken(refreshToken)) {
                    log.info("5");

                    String reissueRefreshToken = tokenProvider.reissueRefreshToken(refreshToken);
                    setTokenInCookie(response, reissueRefreshToken);
                }
            } else {
                log.info("6");

                throw new TokenException(TOKEN_EXPIRED);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(String accessToken) {
        Authentication authentication = tokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        log.info("7");
        String[] excludePath = {"/auth/**", "/", "/swagger-ui/**"};
        String path = request.getRequestURI();
        return Arrays.stream(excludePath).anyMatch(path::startsWith);
    }
}