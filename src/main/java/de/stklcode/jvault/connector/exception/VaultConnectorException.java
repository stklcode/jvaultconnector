package de.stklcode.jvault.connector.exception;

/**
 * Abstract Exception class for Vault Connector internal exceptions.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public abstract class VaultConnectorException extends Exception {
    public VaultConnectorException() {
    }

    public VaultConnectorException(String message) {
        super(message);
    }

    public VaultConnectorException(Throwable cause) {
        super(cause);
    }

    public VaultConnectorException(String message, Throwable cause) {
        super(message, cause);
    }
}
