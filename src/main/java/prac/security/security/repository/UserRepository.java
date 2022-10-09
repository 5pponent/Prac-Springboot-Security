package prac.security.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import prac.security.security.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
