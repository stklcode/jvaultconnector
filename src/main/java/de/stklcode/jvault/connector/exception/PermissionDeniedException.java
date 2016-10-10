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
