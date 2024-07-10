package DY.HaeDollarGo_Spring.security.jwt.error;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static DY.HaeDollarGo_Spring.global.CustomServletException.sendJsonError;
import static DY.HaeDollarGo_Spring.global.ErrorCode.EXPIRE_TOKEN;
import static DY.HaeDollarGo_Spring.global.ErrorCode.ILLEGAL_TOKEN;

@Component
public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            SecurityContextHolder.clearContext();
            sendJsonError(response,EXPIRE_TOKEN.getStatus().value(),EXPIRE_TOKEN.getCode());
        } catch (MalformedJwtException e) {
            SecurityContextHolder.clearContext();
            sendJsonError(response, ILLEGAL_TOKEN.getStatus().value(), ILLEGAL_TOKEN.getCode());
        } catch (JwtException | SecurityException | IllegalArgumentException e){
            SecurityContextHolder.clearContext();
            sendJsonError(response, ILLEGAL_TOKEN.getStatus().value(), ILLEGAL_TOKEN.getCode());
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().equals("/auth/**");
    }
}
