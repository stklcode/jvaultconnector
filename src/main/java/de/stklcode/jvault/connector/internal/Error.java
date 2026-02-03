/*
 * Copyright 2016-2026 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.internal;

/**
 * Utility class to bundle common error messages.
 *
 * @author Stefan Kalscheuer
 * @since 0.8 Extracted from static inner class.
 */
final class Error {
    static final String READ_RESPONSE = "Unable to read response";
    static final String PARSE_RESPONSE = "Unable to parse response";
    static final String UNEXPECTED_RESPONSE = "Received response where none was expected";
    static final String URI_FORMAT = "Invalid URI format";
    static final String RESPONSE_CODE = "Invalid response code";
    static final String INIT_SSL_CONTEXT = "Unable to initialize SSLContext";
    static final String CONNECTION = "Unable to connect to Vault server";

    /**
     * Constructor hidden, this class should not be instantiated.
     */
    private Error() {
    }
}
