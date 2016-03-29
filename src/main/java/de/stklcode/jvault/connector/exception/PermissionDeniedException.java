package de.stklcode.jvault.connector.exception;

/**
 * Exception thrown when trying to access a path the current user/token does not have permission to access.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class PermissionDeniedException extends VaultConnectorException {
    public PermissionDeniedException() {
        super("Permission denied");
    }

    public PermissionDeniedException(String message) {
        super(message);
    }

    public PermissionDeniedException(Throwable cause) {
        super(cause);
    }

    public PermissionDeniedException(String message, Throwable cause) {
        super(message, cause);
    }
}
