package DY.HaeDollarGo_Spring.domain.auth;

import DY.HaeDollarGo_Spring.common.BaseEntity;
import DY.HaeDollarGo_Spring.common.Role;
import DY.HaeDollarGo_Spring.common.SocialType;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Id
    @GeneratedValue
    @Column(name = "user_id")
    private String id;

    @Column(name = "email")
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "social_type")
    @Enumerated(EnumType.STRING)
    private SocialType socialType;

    @Column(name = "role")
    @Enumerated(EnumType.STRING)
    private Role role;

    @Column(name = "profile")
    private String profile;

    @Column(name = "nickname",unique = true)
    private String nickName;
}
