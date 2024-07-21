package DY.HaeDollarGo_Spring.api.auth.jwt;

import DY.HaeDollarGo_Spring.api.auth.domain.BlackList;
import DY.HaeDollarGo_Spring.api.auth.domain.RefreshToken;
import DY.HaeDollarGo_Spring.api.auth.exception.TokenException;
import DY.HaeDollarGo_Spring.api.auth.repository.BlackListRepository;
import DY.HaeDollarGo_Spring.api.auth.repository.RefreshTokenRepository;
import DY.HaeDollarGo_Spring.global.common.TokenValue;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RequiredArgsConstructor
@Component
public class TokenProvider {

    @Value("${jwt.secret.key}")
    private String key;
    private SecretKey secretKey;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BlackListRepository blackListRepository;

    private static final String KEY_ROLE = "role";
    private static final String ACCESS = "Authorization-Access";
    private static final String REFRESH = "Authorization-Refresh";

    @PostConstruct
    private void setSecretKey() {
        secretKey = Keys.hmacShaKeyFor(key.getBytes());
    }

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, TokenValue.ACCESS_TTL, ACCESS);
    }

    public String generateRefreshToken(Authentication authentication) {
        String refreshToken = generateToken(authentication, TokenValue.REFRESH_TTL, REFRESH);
        saveOrUpdate(authentication.getName(), refreshToken);

        return refreshToken;
    }

    private String generateToken(Authentication authentication, long expireTime, String tokenType) {
        Date now = new Date();
        Date expiredDate = new Date(now.getTime() + expireTime);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining());

        return Jwts.builder()
                .subject(tokenType)
                .claim(KEY_ROLE, authorities)
                .issuedAt(now)
                .expiration(expiredDate)
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);
        List<SimpleGrantedAuthority> authorities = getAuthorities(claims);

        User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    private List<SimpleGrantedAuthority> getAuthorities(Claims claims) {
        return Collections.singletonList(new SimpleGrantedAuthority(
                claims.get(KEY_ROLE).toString()));
    }

    public String reissueToken(String token) {
        if (validateToken(token)) {
            if (existsTokenInRefresh(token)) {
                return generateAccessToken(getAuthentication(token));
            }
        }

        return null;
    }

    boolean validateToken(String token) {
        if (StringUtils.hasText(token) && !existsTokenInBlackList(token)) {
            Claims claims = parseClaims(token);
            return claims.getExpiration().after(new Date());
        }
        return false;
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parser().verifyWith(secretKey).build()
                    .parseSignedClaims(token).getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenException(TOKEN_EXPIRED);
        } catch (MalformedJwtException e) {
            throw new TokenException(INVALID_TOKEN);
        } catch (SecurityException e) {
            throw new TokenException(INVALID_SIGNATURE);
        }
    }

    public Long getExpiration(String token) {
        return parseClaims(token).getExpiration().getTime();
    }

    public String resolveTokenInHeader(HttpServletRequest request) {
        String token = request.getHeader(AUTHORIZATION);
        if (ObjectUtils.isEmpty(token) || !token.startsWith(TokenValue.TOKEN_PREFIX)) {
            return null;
        }
        return token.substring(TokenValue.TOKEN_PREFIX.length());
    }

    private String resolveTokenInCookie(String token) {
        if (ObjectUtils.isEmpty(token) || !token.startsWith(TokenValue.TOKEN_PREFIX)) {
            return null;
        }
        return token.substring(TokenValue.TOKEN_PREFIX.length());
    }

    public String getRefreshTokenInCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("Authorization-Refresh".equals(cookie.getName())) {
                    String refreshToken = resolveTokenInCookie(cookie.getValue());
                    if (StringUtils.hasText(refreshToken)) {
                        return refreshToken;
                    }
                }
            }
        }
        return null;
    }

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
}