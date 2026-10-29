package de.nalto.identityServer.services;

import de.nalto.identityServer.dto.UserInfo;
import de.nalto.identityServer.dto.UserRegistration;
import de.nalto.identityServer.exceptions.UserNotFoundException;
import de.nalto.identityServer.exceptions.UserUpdateException;
import de.nalto.identityServer.persistence.model.Authority;
import de.nalto.identityServer.persistence.model.User;
import de.nalto.identityServer.persistence.repositories.AuthorityRepository;
import de.nalto.identityServer.persistence.repositories.UserRepository;
import de.nalto.identityServer.utils.Validator;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final PasswordEncoder encoder;
    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private static final String userRole = "ROLE_USER";

    public UserService(PasswordEncoder encoder, UserRepository userRepository,
                       AuthorityRepository authorityRepository) {
        this.encoder = encoder;
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
    }

    @Transactional
    public void register(UserRegistration registration) {
        if (!Validator.isValidEmail(registration.email())) {
            throw new IllegalArgumentException("Invalid email address");
        }
        if (!Validator.isValidUsername(registration.username())) {
            throw new IllegalArgumentException("Invalid username");
        }

        User user = new User();
        Authority authority = new Authority();

        authority.setAuthority(userRole);
        authority.setUsername(registration.username());

        user.setUsername(registration.username());
        user.setPassword(encoder.encode(registration.password()));
        user.setEnabled(true); // TODO add email verification
        user.setEmail(registration.email());
        user.setAuthorities(List.of(authority));

        userRepository.save(user);
    }

    public UserInfo getUser(Long id) throws UserNotFoundException {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User with id " + id + " not found"));
        return toInfo(user);
    }

    public UserInfo getUserInfo(String username) throws UserNotFoundException {
        return toInfo(findUser(username));
    }

    @Transactional
    public void updateEmail(String username, String email) throws UserNotFoundException {
        User user = findUser(username);
        if (!Validator.isValidEmail(email)) {
            throw new UserUpdateException("invalid.email");
        }
        if (!email.equals(user.getEmail()) && userRepository.existsByEmail(email)) {
            throw new UserUpdateException("email.taken");
        }
        user.setEmail(email);
        userRepository.save(user);
    }

    @Transactional
    public void updateUsername(String username, String newUsername) throws UserNotFoundException {
        User user = findUser(username);
        if (!Validator.isValidUsername(newUsername)) {
            throw new UserUpdateException("invalid.username");
        }
        if (!newUsername.equals(username) && userRepository.existsByUsername(newUsername)) {
            throw new UserUpdateException("username.taken");
        }
        if (newUsername.equals(username)) {
            return;
        }
        List<Authority> authorities = List.copyOf(authorityRepository.findByUsername(username));
        user.setUsername(newUsername);
        userRepository.saveAndFlush(user);
        for (Authority authority : authorities) {
            authority.setUsername(newUsername);
        }
        authorityRepository.saveAll(authorities);
    }

    @Transactional
    public void updatePassword(String username, String currentPassword, String newPassword)
            throws UserNotFoundException {
        User user = findUser(username);
        if (currentPassword == null || !encoder.matches(currentPassword, user.getPassword())) {
            throw new UserUpdateException("invalid.current.password");
        }
        if (newPassword == null || newPassword.isEmpty()) {
            throw new UserUpdateException("invalid.new.password");
        }
        user.setPassword(encoder.encode(newPassword));
        userRepository.save(user);
    }

    private User findUser(String username) throws UserNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User with username " + username + " not found"));
    }

    private UserInfo toInfo(User user) {
        return new UserInfo(user.getId(), user.getUsername(), user.getEmail());
    }
}
