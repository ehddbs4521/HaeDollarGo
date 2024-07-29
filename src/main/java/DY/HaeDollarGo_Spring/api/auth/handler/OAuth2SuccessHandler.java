package DY.HaeDollarGo_Spring.api.auth.handler;

import DY.HaeDollarGo_Spring.api.auth.jwt.TokenProvider;
import DY.HaeDollarGo_Spring.api.auth.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private static final String URI = "/auth/success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        String accessToken = tokenProvider.generateAccessToken(authentication);
        String refreshToken = tokenProvider.generateRefreshToken(authentication);

        String redirectUrl = UriComponentsBuilder.fromUriString(URI)
                .build().toUriString();

        TokenService.setTokenInHeader(response, accessToken);
        TokenService.setTokenInCookie(response, refreshToken);

        response.sendRedirect(redirectUrl);
    }
}
