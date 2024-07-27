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

        log.info("url: {}", request.getRequestURI());
        if (isUnprotectedEndpoint(request)) {

            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = tokenProvider.resolveTokenInHeader(request);

        if (tokenProvider.validateToken(accessToken)) {
            setAuthentication(accessToken);
        } else {
            if (request.getRequestURI().equals("/auth/reissue")) {
                String refreshTokenInCookie = tokenProvider.getRefreshTokenInCookie(request);
                String reissueAccessToken = tokenProvider.reissueToken(refreshTokenInCookie);
                if (StringUtils.hasText(reissueAccessToken)) {
                    setAuthentication(reissueAccessToken);
                    response.setHeader(AUTHORIZATION, TokenValue.TOKEN_PREFIX + reissueAccessToken);
                } else {
                    throw new TokenException(NOT_EXIST_REFRESHTOKEN);
                }
            } else {
                throw new TokenException(TOKEN_EXPIRED);
            }

        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(String accessToken) {
        Authentication authentication = tokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private boolean isUnprotectedEndpoint(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.equals("/") || uri.equals("/auth/success") || uri.equals("/favicon.ico");
    }
}
