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
