/*
 * Copyright 2016 Stefan Kalscheuer
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
 * Exception thrown on errors with TLS connection.
 *
 * @author  Stefan Kalscheuer
 * @since   0.4.0
 */
public class TlsException extends VaultConnectorException {
    private Integer statusCode;
    private String response;

    public TlsException() {
    }

    public TlsException(String message) {
        super(message);
    }

    public TlsException(Throwable cause) {
        super(cause);
    }

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getResponse() {
        return response;
    }
}