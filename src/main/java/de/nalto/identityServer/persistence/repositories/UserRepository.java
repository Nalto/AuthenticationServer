package de.nalto.identityServer.persistence.repositories;

import de.nalto.identityServer.persistence.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
