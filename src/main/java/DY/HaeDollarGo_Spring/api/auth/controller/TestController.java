package DY.HaeDollarGo_Spring.api.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/")
    public String test(HttpServletResponse response) {
        String key = response.getHeader("Authorization-Access");

        return key;
    }
}
