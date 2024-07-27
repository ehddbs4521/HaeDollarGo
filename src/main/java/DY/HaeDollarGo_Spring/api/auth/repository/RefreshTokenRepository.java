package DY.HaeDollarGo_Spring.api.auth.repository;

import DY.HaeDollarGo_Spring.api.auth.domain.RefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {

}
