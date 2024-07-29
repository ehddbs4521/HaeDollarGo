package DY.HaeDollarGo_Spring.api.auth.repository;

import DY.HaeDollarGo_Spring.api.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserKey(String userKey);
}
