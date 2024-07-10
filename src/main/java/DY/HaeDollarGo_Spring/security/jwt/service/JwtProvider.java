package DY.HaeDollarGo_Spring.security.jwt.service;


import DY.HaeDollarGo_Spring.security.UserDetailsServiceImpl;
import DY.HaeDollarGo_Spring.security.jwt.dto.response.TokenResponse;
import DY.HaeDollarGo_Spring.security.redis.RedisService;
import io.jsonwebtoken.*;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;

import static io.jsonwebtoken.Jwts.builder;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@Getter
@Service
@Transactional(readOnly = true)
public class JwtProvider {

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL = "email";
    private static final String SOCIAL_TYPE = "socialType";
    private static final String ID = "id";
    private static final String BEARER = "Bearer ";
    private static final String AUTHORITIES_KEY = "role";
    private static final String LOGOUT = "logout";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 2;            // 유효기간 2시간
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 14;  // 유효기간 14일

    private String accessHeader;
    private String refreshHeader;
    private final SecretKey key;
    private final UserDetailsServiceImpl userDetailsService;
    private final RedisService redisService;

    public JwtProvider(@Value("${jwt.secret.key}") String secret,
                       @Value("${jwt.secret.header.access}") String accessHeader,
                       @Value("${jwt.secret.header.refresh}") String refreshHeader, UserDetailsServiceImpl userDetailsService, RedisService redisService) {
        this.accessHeader = accessHeader;
        this.refreshHeader = refreshHeader;
        this.userDetailsService = userDetailsService;
        this.redisService = redisService;
        byte[] keyBytes = Base64.getDecoder().decode(secret.getBytes(UTF_8));
        this.key = new SecretKeySpec(keyBytes, "HmacSHA512");
    }

    public TokenResponse generateToken(String email, String socialType, String authorities) {

        long now = (new Date()).getTime();
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);
        Date refreshTokenExpiresIn = new Date(now + REFRESH_TOKEN_EXPIRE_TIME);

        String accessToken = builder()
                .setSubject("access-token")
                .claim(EMAIL, email)
                .claim(SOCIAL_TYPE, socialType)
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        String refreshToken = builder()
                .setSubject("refresh-token")
                .claim(EMAIL, email)
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(refreshTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return new TokenResponse(accessToken, refreshToken);
    }

   public Claims getClaims(String token){
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
   }

    public Authentication getAuthentication(String token) {
        String email = getClaims(token).get(EMAIL).toString();
        String socialType = getClaims(token).get(SOCIAL_TYPE).toString();
        UserDetails userDetails = userDetailsService.loadUserByEmailAndSocialType(email, socialType);
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public Authentication getAuthenticationByRefreshToken(String refreshToken) {
        String email = getClaims(refreshToken).get(EMAIL).toString();
        String socialType = getClaims(refreshToken).get(SOCIAL_TYPE).toString();
        UserDetails userDetails = userDetailsService.loadUserByEmailAndSocialType(email, socialType);

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }
    public long getTokenExpirationTime(String token){
        return getClaims(token).getExpiration().getTime();
    }


    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature.");
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.");
        } catch (NullPointerException e) {
            log.error("JWT Token is empty.");
        }
        return false;
    }

    public boolean validateAccessToken(String accessToken) {
        String redisServiceValues = redisService.getValues(accessToken);

        try {
            if (redisServiceValues != null && redisServiceValues.equals(LOGOUT)) {
                return false;
            }
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(accessToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature.");
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.");
        } catch (NullPointerException e) {
            log.error("JWT Token is empty.");
        }
        return false;
    }

    public boolean validateAccessTokenOnlyExpired(String accessToken) {
        try {
            return getClaims(accessToken)
                    .getExpiration()
                    .before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

