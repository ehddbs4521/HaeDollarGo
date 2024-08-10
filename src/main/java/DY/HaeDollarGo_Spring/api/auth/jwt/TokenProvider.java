package DY.HaeDollarGo_Spring.api.auth.jwt;

import DY.HaeDollarGo_Spring.api.auth.exception.TokenException;
import DY.HaeDollarGo_Spring.api.auth.service.RedisService;
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
import lombok.extern.slf4j.Slf4j;
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
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.*;
import static DY.HaeDollarGo_Spring.global.common.TokenValue.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@RequiredArgsConstructor
@Component
public class TokenProvider {

    @Value("${jwt.secret.key}")
    private String key;
    private SecretKey secretKey;
    private static final String USER_KEY = "user";
    private static final String KEY_ROLE = "role";
    private final RedisService redisService;
    @PostConstruct
    private void setSecretKey() {
        secretKey = Keys.hmacShaKeyFor(key.getBytes());
    }

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, TokenValue.ACCESS_TTL, ACCESS_HEADER);
    }

    public String generateRefreshToken(Authentication authentication) {
        String refreshToken = generateToken(authentication, REFRESH_TTL, REFRESH_HEADER);
        saveOrUpdate(refreshToken);

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
                .claim(USER_KEY, authentication.getName())
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

    public String reissueAccessToken(String token) {
        if (validateToken(token)) {
            if (existsTokenInRefresh(token)) {
                return generateAccessToken(getAuthentication(token));
            }
        }
        return null;
    }

    public String reissueRefreshToken(String token) {

        return generateRefreshToken(getAuthentication(token));
    }

    boolean validateToken(String token) {
        if (StringUtils.hasText(token)) {
            log.info("good!");
            parseClaims(token);
            return true;
        }
        return false;
    }

    public Date extractTime(String accessToken) {

        return parseClaims(accessToken).getExpiration();
    }

    public Claims parseClaims(String token) {
        try {
            log.info("first");
            return Jwts.parser().verifyWith(secretKey).build()
                    .parseSignedClaims(token).getPayload();
        } catch (ExpiredJwtException e) {
            log.info("second");
            throw new TokenException(TOKEN_EXPIRED);
        } catch (MalformedJwtException e) {
            log.info("third");
            throw new TokenException(INVALID_TOKEN);
        } catch (SecurityException e) {
            log.info("fourth");
            throw new TokenException(INVALID_SIGNATURE);
        }
    }

    public String resolveTokenInHeader(HttpServletRequest request) {
        log.info("sadad");
        String token = request.getHeader(ACCESS_HEADER);
        if (ObjectUtils.isEmpty(token) || !token.startsWith(TokenValue.TOKEN_PREFIX)) {
            log.info("sb");
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
                if (REFRESH_HEADER.equals(cookie.getName())) {
                    String refreshToken = resolveTokenInCookie(cookie.getValue());
                    if (StringUtils.hasText(refreshToken)) {
                        return refreshToken;
                    }
                }
            }
        }
        return null;
    }

    public boolean existsTokenInRefresh(String token) {
        String userKey = redisService.getValue(token);
        return userKey != null;
    }

    public Long calculateTimeLeft(String token) {
        Instant expirationTime = extractTime(token).toInstant();
        Instant now = LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant();
        return Duration.between(now, expirationTime).getSeconds();
    }

    @Transactional
    public void saveOrUpdate(String refreshToken) {

        String userKey = redisService.getValue(refreshToken);
        if (userKey == null) {
            userKey = parseClaims(refreshToken).get(USER_KEY).toString();
            redisService.saveValue(refreshToken, userKey, REFRESH_TTL);
        } else {
            Long ttl = calculateTimeLeft(refreshToken);
            redisService.saveValue(refreshToken, userKey, ttl);
        }
    }

    public boolean isRotateToken(String refreshToken) {
        Instant issuedInstant = parseClaims(refreshToken).getIssuedAt().toInstant();
        return Instant.now().isAfter(issuedInstant.plus(24, ChronoUnit.HOURS));
    }
}