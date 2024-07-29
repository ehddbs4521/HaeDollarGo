package DY.HaeDollarGo_Spring.api.auth.service;

import DY.HaeDollarGo_Spring.api.auth.jwt.TokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final TokenProvider tokenProvider;
    private final TokenService tokenService;


    public void logout(HttpServletRequest request) {
        String accessToken = tokenProvider.resolveTokenInHeader(request);
        String refreshToken = tokenProvider.getRefreshTokenInCookie(request);
        tokenService.updateToken(accessToken,refreshToken);
    }
}
