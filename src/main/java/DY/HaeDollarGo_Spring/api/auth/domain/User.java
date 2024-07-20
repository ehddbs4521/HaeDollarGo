package DY.HaeDollarGo_Spring.api.auth.domain;

import DY.HaeDollarGo_Spring.global.common.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private String id;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "social_type", nullable = false)
    private String socialType;

    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    @Column(name = "profile", nullable = false)
    private String profile;

    @Column(name = "user_key", nullable = false, unique = true)
    private String userKey;

    @Column(name = "nickname", nullable = false, unique = true)
    private String nickName;

    @Builder
    public User(String id, String email, String socialType, Role role, String profile, String userKey, String nickName) {
        this.id = id;
        this.email = email;
        this.socialType = socialType;
        this.role = role;
        this.profile = profile;
        this.userKey = userKey;
        this.nickName = nickName;
    }
}
