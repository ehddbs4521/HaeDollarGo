package DY.HaeDollarGo_Spring.api.auth.jwt;

import DY.HaeDollarGo_Spring.api.auth.exception.TokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class TokenExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (isUnprotectedEndpoint(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            filterChain.doFilter(request, response);
        } catch (TokenException e) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            ObjectMapper objectMapper = new ObjectMapper();
            String errorJson = objectMapper.writeValueAsString(e);
            response.getWriter().print(errorJson);
        }
    }

    private boolean isUnprotectedEndpoint(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.equals("/") || uri.equals("/api-docs");

    }
}
