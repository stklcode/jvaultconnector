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
import de.stklcode.jvault.connector.model.Token;
import de.stklcode.jvault.connector.model.TokenRole;
import de.stklcode.jvault.connector.model.response.AuthResponse;
import de.stklcode.jvault.connector.model.response.TokenResponse;
import de.stklcode.jvault.connector.model.response.TokenRoleResponse;

import java.util.List;

/**
 * Token client interface.
 * Provides methods to interact with Vault's token API.
 *
 * @since 2.0.0 extracted from {@link VaultConnector}
 */
public interface TokenClient {

    /**
     * Create a new token.
     *
     * @param token the token
     * @return the result response
     * @throws VaultConnectorException on error
     */
    AuthResponse create(final Token token) throws VaultConnectorException;

    /**
     * Create a new token.
     *
     * @param token  the token
     * @param orphan create orphan token
     * @return the result response
     * @throws VaultConnectorException on error
     */
    AuthResponse create(final Token token, boolean orphan) throws VaultConnectorException;

    /**
     * Create a new token for specific role.
     *
     * @param token the token
     * @param role  the role name
     * @return the result response
     * @throws VaultConnectorException on error
     */
    AuthResponse create(final Token token, final String role) throws VaultConnectorException;

    /**
     * Lookup token information.
     *
     * @param token the token
     * @return the result response
     * @throws VaultConnectorException on error
     */
    TokenResponse lookup(final String token) throws VaultConnectorException;

    /**
     * Create a new or update an existing token role.
     *
     * @param role the role entity (name must be set)
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    default boolean createOrUpdateRole(final TokenRole role) throws VaultConnectorException {
        return createOrUpdateRole(role.getName(), role);
    }

    /**
     * Create a new or update an existing token role.
     *
     * @param name the role name (overrides name possibly set in role entity)
     * @param role the role entity
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    boolean createOrUpdateRole(final String name, final TokenRole role) throws VaultConnectorException;

    /**
     * Lookup token information.
     *
     * @param name the role name
     * @return the result response
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    TokenRoleResponse readRole(final String name) throws VaultConnectorException;

    /**
     * List available token roles from Vault.
     *
     * @return List of token roles
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    List<String> listRoles() throws VaultConnectorException;

    /**
     * Delete a token role.
     *
     * @param name the role name to delete
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    boolean deleteRole(final String name) throws VaultConnectorException;
}
