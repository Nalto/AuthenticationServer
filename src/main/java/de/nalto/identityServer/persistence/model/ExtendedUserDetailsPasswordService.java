package de.nalto.identityServer.persistence.model;

import org.jspecify.annotations.Nullable;

public interface ExtendedUserDetailsPasswordService {

    ExtendedUserDetails updatePassword(ExtendedUserDetails user, @Nullable String newPassword);
}
