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

package de.stklcode.jvault.connector;

import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.response.CredentialsResponse;

/**
 * Database backend client interface.
 * Provides methods to interact with Vault's DB APIs.
 *
 * @since 2.0.0
 */
public interface DbClient {

    /**
     * Read credentials for database backend.
     *
     * @param role  the role name
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     * @since 2.0.0 removed {@code mount} parameer
     */
    CredentialsResponse readCredentials(final String role) throws VaultConnectorException;

}
