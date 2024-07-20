package DY.HaeDollarGo_Spring.api.auth.repository;

import DY.HaeDollarGo_Spring.api.auth.domain.BlackList;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BlackListRepository extends CrudRepository<BlackList,String> {

    @Override
    Optional<BlackList> findById(String token);

}
