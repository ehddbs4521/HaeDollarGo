package DY.HaeDollarGo_Spring.global;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomServletException {

    public static void sendJsonError(HttpServletResponse response, int statusCode, String code) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(statusCode);
        String jsonError = String.format("{\"status\": \"%d\", \"code\": \"%s\"}", statusCode, code);
        response.getWriter().write(jsonError);
    }
}
