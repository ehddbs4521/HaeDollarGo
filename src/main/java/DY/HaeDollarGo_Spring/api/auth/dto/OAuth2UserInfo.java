package DY.HaeDollarGo_Spring.api.auth.dto;

import DY.HaeDollarGo_Spring.api.auth.domain.Role;
import DY.HaeDollarGo_Spring.api.auth.domain.User;
import DY.HaeDollarGo_Spring.api.auth.exception.AuthException;
import DY.HaeDollarGo_Spring.api.util.RandomCreater;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.UUID;

import static DY.HaeDollarGo_Spring.api.exception.ErrorCode.WRONG_REGISTRATION_ID;

@Slf4j
@Getter
@Builder
@RequiredArgsConstructor
public class OAuth2UserInfo {

    private final String email;
    private final String profile;
    private final String nickName;
    private final String userKey;
    private final String socialType;

    public static OAuth2UserInfo of(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId) {
            case "google" -> ofGoogle(attributes);
            case "kakao" -> ofKakao(attributes);
            case "naver" -> ofNaver(attributes);
            default -> throw new AuthException(WRONG_REGISTRATION_ID);
        };
    }

    private static OAuth2UserInfo ofGoogle(Map<String, Object> attributes) {

        String googleUserKey = (String) attributes.get("sub");

        return OAuth2UserInfo.builder()
                .nickName(RandomCreater.generateKey())
                .email((String) attributes.get("email"))
                .profile((String) attributes.get("picture"))
                .userKey(googleUserKey)
                .socialType("Google")
                .build();
    }

    private static OAuth2UserInfo ofKakao(Map<String, Object> attributes) {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");
        String kakaoUserKey = String.valueOf(attributes.get("id"));

        return OAuth2UserInfo.builder()
                .nickName(RandomCreater.generateKey())
                .email((String) account.get("email"))
                .profile((String) profile.get("profile_image_url"))
                .userKey(kakaoUserKey)
                .socialType("Kakao")
                .build();
    }

    private static OAuth2UserInfo ofNaver(Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        String naverUserKey = (String) response.get("id");

        return OAuth2UserInfo.builder()
                .nickName(RandomCreater.generateKey())
                .email((String) response.get("email"))
                .profile((String) response.get("profile_image"))
                .userKey(naverUserKey)
                .socialType("Naver")
                .build();
    }


    public User toEntity() {
        return User.builder()
                .email(email)
                .socialType(socialType)
                .role(Role.User)
                .profile(profile)
                .userKey(userKey)
                .nickName(nickName)
                .build();
    }
}
