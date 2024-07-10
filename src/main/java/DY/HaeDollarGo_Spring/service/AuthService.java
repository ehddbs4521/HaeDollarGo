package DY.HaeDollarGo_Spring.service;

import DY.HaeDollarGo_Spring.domain.auth.User;
import DY.HaeDollarGo_Spring.global.CustomException;
import DY.HaeDollarGo_Spring.global.ErrorCode;
import DY.HaeDollarGo_Spring.repository.UserRepository;
import DY.HaeDollarGo_Spring.security.jwt.dto.response.TokenResponse;
import DY.HaeDollarGo_Spring.security.jwt.service.JwtProvider;
import DY.HaeDollarGo_Spring.security.login.dto.LoginRequest;
import DY.HaeDollarGo_Spring.security.redis.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final RedisService redisService;

    private final String LOGOUT ="logout";

    @Transactional
    public TokenResponse login(LoginRequest loginRequest) {

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return generateToken(loginRequest.getEmail(), loginRequest.getSocialType(), getAuthorities(authentication));

    }

    @Transactional
    public void logout(String accessTokenInHeader) {
        String accessToken = resolveToken(accessTokenInHeader);
        String email = getEmail(accessToken);
        String socialType = getSocialType(accessToken);

        String refreshToken = redisService.getValues("RT(" + email + "_" + socialType + ")");
        if (refreshToken != null) {
            redisService.deleteValues("RT(" + email + "_" + socialType + ")");
        }

        long expiration = jwtProvider.getTokenExpirationTime(refreshToken) - new Date().getTime();
        redisService.setValuesWithTimeout(accessToken, LOGOUT, expiration);
    }

    @Transactional
    public TokenResponse generateToken(String email, String socialType, String authorities) {

        if (redisService.getValues("RT(" + email + "_" + socialType + ")") != null) {
            redisService.deleteValues("RT(" + email + "_" + socialType + ")");
        }

        TokenResponse tokenResponse = jwtProvider.generateToken(email, socialType, authorities);

        return tokenResponse;
    }

    public String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

    @Transactional
    public void saveRefreshToken(String email, String socialType, String refreshToken) {
        redisService.setValuesWithTimeout("RT(" + email + "_" + socialType + ")",
                refreshToken,
                jwtProvider.getTokenExpirationTime(refreshToken));
    }

    public String resolveToken(String accessToken) {
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            return accessToken.substring(7);
        }
        return null;
    }

    public String getEmail(String accessToken) {
        return jwtProvider.getClaims(accessToken).get("email").toString();
    }

    public String getSocialType(String accessToken) {
        return jwtProvider.getClaims(accessToken).get("socialType").toString();
    }

    @Transactional
    public TokenResponse reissue(String requestRefreshTokenInHeader, String socialType) {

        Authentication authentication = jwtProvider.getAuthenticationByRefreshToken(requestRefreshTokenInHeader);
        String email = getPrincipalByRefreshToken(requestRefreshTokenInHeader);

        String refreshTokenInRedis = redisService.getValues("RT(" + email + "_" + socialType + ")");
        if (refreshTokenInRedis == null) {
            return null; // -> 재로그인 요청
        }

        // RT의 유효성 검사
        if (!jwtProvider.validateRefreshToken(refreshTokenInRedis)) {
            redisService.deleteValues("RT(" + email + "_" + socialType + ")"); // 삭제
            return null; // -> 재로그인 요청
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String authorities = getAuthorities(authentication);

        redisService.deleteValues("RT(" + email + "_" + socialType + ")"); // 기존 RT 삭제
        TokenResponse tokenDto = jwtProvider.generateToken(email, socialType, authorities);
        saveRefreshToken(email, socialType, tokenDto.getRefreshToken());
        return tokenDto;
    }

    public String getPrincipalByRefreshToken(String requestRefreshToken) {
        return jwtProvider.getAuthenticationByRefreshToken(requestRefreshToken).getName();
    }

}
