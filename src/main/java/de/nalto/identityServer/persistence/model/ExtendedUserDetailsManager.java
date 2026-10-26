package de.nalto.identityServer.persistence.model;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.nio.file.AccessDeniedException;

public interface ExtendedUserDetailsManager extends UserDetailsService {
    /**
     * Create a new user with the supplied details.
     */
    void createUser(ExtendedUserDetails user);

    /**
     * Update the specified user.
     */
    void updateUser(ExtendedUserDetails user);

    /**
     * Remove the user with the given login name from the system.
     */
    void deleteUser(String username);

    /**
     * Modify the current user's password. This should change the user's password in the
     * persistent user repository (database, LDAP etc).
     * @param oldPassword current password (for re-authentication if required)
     * @param newPassword the password to change to
     */
    void changePassword(@Nullable String oldPassword, @Nullable String newPassword) throws AccessDeniedException;

    /**
     * Check if a user with the supplied login name exists in the system.
     */
    boolean userExists(String username);
}
