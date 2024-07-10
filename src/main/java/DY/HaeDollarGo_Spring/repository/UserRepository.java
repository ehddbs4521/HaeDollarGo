package DY.HaeDollarGo_Spring.repository;

import DY.HaeDollarGo_Spring.domain.auth.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findById(String id);
    Optional<User> findByEmailAndSocialType(String email, String socialType);

}
