package DY.HaeDollarGo_Spring.api.auth.controller;

import DY.HaeDollarGo_Spring.api.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    @GetMapping("/success")
    public String loginSuccess(HttpServletResponse response) {
        return "success";
    }


    @PostMapping("/logout")
    public ResponseEntity<Object> logout(HttpServletRequest request) {
        authService.logout(request);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
