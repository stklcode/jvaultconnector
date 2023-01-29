/*
 * Copyright 2016-2023 Stefan Kalscheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.stklcode.jvault.connector.exception;

/**
 * Exception thrown when response from vault returned with erroneous status code or payload could not be parsed
 * to entity class.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public final class InvalidResponseException extends VaultConnectorException {
    private final Integer statusCode;
    private final String response;

    /**
     * Constructs a new empty exception.
     */
    public InvalidResponseException() {
        this.statusCode = null;
        this.response = null;
    }

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message
     */
    public InvalidResponseException(final String message) {
        super(message);
        this.statusCode = null;
        this.response = null;
    }

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param cause The cause
     */
    public InvalidResponseException(final Throwable cause) {
        super(cause);
        this.statusCode = null;
        this.response = null;
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message The detail message
     * @param cause   The cause
     */
    public InvalidResponseException(final String message, final Throwable cause) {
        super(message, cause);
        this.statusCode = null;
        this.response = null;
    }

    /**
     * Constructs a new exception with the specified detail message and status code.
     * <p>
     * The HTTP status code can be retrieved by {@link #getStatusCode()} later.
     *
     * @param message    The detail message
     * @param statusCode Status code of the HTTP response
     * @since 0.6.2
     */
    public InvalidResponseException(final String message, final Integer statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.response = null;
    }

    /**
     * Constructs a new exception with the specified detail message, cause and status code.
     * <p>
     * The HTTP status code can be retrieved by {@link #getStatusCode()} later.
     *
     * @param message    The detail message
     * @param statusCode Status code of the HTTP response
     * @param cause      The cause
     * @since 0.6.2
     */
    public InvalidResponseException(final String message, final Integer statusCode, final Throwable cause) {
        this(message, statusCode, null, cause);
    }

    /**
     * Constructs a new exception with the specified detail message, cause and status code.
     * <p>
     * The HTTP status code can be retrieved by {@link #getStatusCode()} later.
     *
     * @param message    The detail message
     * @param statusCode Status code of the HTTP response
     * @param response   HTTP response string
     * @since 0.6.2
     */
    public InvalidResponseException(final String message,
                                    final Integer statusCode,
                                    final String response) {
        super(message);
        this.statusCode = statusCode;
        this.response = response;
    }

    /**
     * Constructs a new exception with the specified detail message, cause and status code.
     * <p>
     * The HTTP status code can be retrieved by {@link #getStatusCode()} later.
     *
     * @param message    The detail message
     * @param statusCode Status code of the HTTP response
     * @param response   HTTP response string
     * @param cause      The cause
     * @since 0.6.2
     */
    public InvalidResponseException(final String message,
                                    final Integer statusCode,
                                    final String response,
                                    final Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
        this.response = response;
    }

    /**
     * Retrieve the HTTP status code.
     *
     * @return The status code or {@code null} if none specified.
     */
    public Integer getStatusCode() {
        return statusCode;
    }

    /**
     * Retrieve the response text.
     *
     * @return The response text or {@code null} if none specified.
     */
    public String getResponse() {
        return response;
    }
}
