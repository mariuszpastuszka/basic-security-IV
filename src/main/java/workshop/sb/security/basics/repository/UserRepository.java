package workshop.sb.security.basics.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import workshop.sb.security.basics.model.User;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {}