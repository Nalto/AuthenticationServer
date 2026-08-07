package de.nalto.identityServer.services;

import de.nalto.identityServer.dto.UserRegistration;
import de.nalto.identityServer.persistence.model.Authority;
import de.nalto.identityServer.persistence.model.User;
import de.nalto.identityServer.persistence.repositories.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final PasswordEncoder encoder;
    private final UserRepository userRepository;
    private static final String userRole = "ROLE_USER";

    public UserService(PasswordEncoder encoder, UserRepository userRepository) {
        this.encoder = encoder;
        this.userRepository = userRepository;
    }

    @Transactional
    public void register(UserRegistration registration) {
        User user = new User();
        Authority authority = new Authority();

        authority.setAuthority(userRole);
        authority.setUsername(registration.username());

        user.setUsername(registration.username());
        user.setPassword(encoder.encode(registration.password()));
        user.setEnabled(false);
        user.setAuthorities(List.of(authority));

        userRepository.save(user);
    }
}
