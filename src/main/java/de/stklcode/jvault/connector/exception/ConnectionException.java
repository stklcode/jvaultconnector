package de.stklcode.jvault.connector.exception;

/**
 * Exception thrown on problems with connection to Vault backend.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class ConnectionException extends VaultConnectorException {
    public ConnectionException() {
    }

    public ConnectionException(String message) {
        super(message);
    }

    public ConnectionException(Throwable cause) {
        super(cause);
    }

    public ConnectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
