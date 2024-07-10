package DY.HaeDollarGo_Spring.security.login.dto;

import lombok.Getter;

@Getter
public class LoginRequest {

    private String email;
    private String password;
    private String socialType;
    private String userType;

    public LoginRequest(String email, String password, String socialType, String userType) {
        this.email = email;
        this.password = password;
        this.socialType = socialType;
        this.userType = userType;
    }
}
