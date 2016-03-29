package de.stklcode.jvault.connector.exception;

/**
 * Exception thrown when response from vault returned with erroneous status code or payload could not be parsed
 * to entity class.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class InvalidResponseException extends VaultConnectorException {
    private Integer statusCode;
    private String response;

    public InvalidResponseException() {
    }

    public InvalidResponseException(String message) {
        super(message);
    }

    public InvalidResponseException(Throwable cause) {
        super(cause);
    }

    public InvalidResponseException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidResponseException withStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
        return this;
    }

    public InvalidResponseException withResponse(String response) {
        this.response = response;
        return this;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getResponse() {
        return response;
    }
}
