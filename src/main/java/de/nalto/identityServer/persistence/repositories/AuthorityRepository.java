package de.nalto.identityServer.persistence.repositories;

import de.nalto.identityServer.persistence.model.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    Collection<Authority> findByUsername(String username);
}
