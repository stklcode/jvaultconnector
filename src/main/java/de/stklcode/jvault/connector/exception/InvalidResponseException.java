/*
 * Copyright 2016-2017 Stefan Kalscheuer
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
    private Integer statusCode;
    private String response;

    /**
     * Constructs a new empty exception.
     */
    public InvalidResponseException() {
    }

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message the detail message
     */
    public InvalidResponseException(final String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param cause the cause
     */
    public InvalidResponseException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause
     */
    public InvalidResponseException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Specify the HTTP status code. Can be retrieved by {@link #getStatusCode()} later.
     *
     * @param statusCode the status code
     * @return self
     */
    public InvalidResponseException withStatusCode(final Integer statusCode) {
        this.statusCode = statusCode;
        return this;
    }

    /**
     * Specify the response string. Can be retrieved by {@link #getResponse()} later.
     *
     * @param response response text
     * @return self
     */
    public InvalidResponseException withResponse(final String response) {
        this.response = response;
        return this;
    }

    /**
     * Retrieve the HTTP status code.
     *
     * @return the status code or {@code null} if none specified.
     */
    public Integer getStatusCode() {
        return statusCode;
    }

    /**
     * Retrieve the response text.
     *
     * @return the response text or {@code null} if none specified.
     */
    public String getResponse() {
        return response;
    }
}
