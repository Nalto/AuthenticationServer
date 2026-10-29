package de.nalto.identityServer.exceptions;

/**
 * Thrown when a user update is rejected. The message is a key of the message bundle.
 */
public class UserUpdateException extends RuntimeException {
    public UserUpdateException(String messageKey) {
        super(messageKey);
    }
}
