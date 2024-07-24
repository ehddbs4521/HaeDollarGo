package DY.HaeDollarGo_Spring.api.auth.jwt;

import DY.HaeDollarGo_Spring.api.auth.exception.TokenException;
import DY.HaeDollarGo_Spring.api.auth.service.TokenService;
import DY.HaeDollarGo_Spring.global.common.TokenValue;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.NOT_EXIST_REFRESHTOKEN;
import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.TOKEN_EXPIRED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RequiredArgsConstructor
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String accessToken = tokenProvider.resolveTokenInHeader(request);

        if (request.getRequestURI().equals("/")) {
            filterChain.doFilter(request, response);
        }

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


}
