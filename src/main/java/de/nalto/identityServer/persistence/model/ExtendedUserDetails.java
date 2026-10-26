package de.nalto.identityServer.persistence.model;

import org.springframework.security.core.userdetails.UserDetails;

public interface ExtendedUserDetails extends UserDetails {
    public void setPassword(String password);
}
