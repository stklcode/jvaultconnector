package de.stklcode.jvault.connector.exception;

/**
 * Exception thrown when trying to send malformed request.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class InvalidRequestException extends VaultConnectorException {
    public InvalidRequestException() {
    }

    public InvalidRequestException(String message) {
        super(message);
    }

    public InvalidRequestException(Throwable cause) {
        super(cause);
    }

    public InvalidRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
