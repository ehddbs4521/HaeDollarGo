package DY.HaeDollarGo_Spring.controller;

import DY.HaeDollarGo_Spring.security.login.dto.LoginRequest;
import DY.HaeDollarGo_Spring.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public void login(@RequestBody LoginRequest loginRequest) {
        authService.login(loginRequest);
    }


}
