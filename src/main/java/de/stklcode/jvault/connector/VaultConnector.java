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
import de.stklcode.jvault.connector.model.response.*;

import java.io.Serializable;
import java.util.*;

/**
 * Vault Connector interface.
 * Provides methods to connect with Vault backend and handle secrets.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public interface VaultConnector extends AutoCloseable, Serializable {

    /**
     * Reset authorization information.
     */
    void resetAuth();

    /**
     * Authorize to Vault using token.
     *
     * @param token The token
     * @return Token response
     * @throws VaultConnectorException on error
     */
    TokenResponse authToken(final String token) throws VaultConnectorException;

    /**
     * Authorize to Vault using username and password.
     *
     * @param username The username
     * @param password The password
     * @return Authorization result
     * @throws VaultConnectorException on error
     */
    AuthResponse authUserPass(final String username, final String password) throws VaultConnectorException;

    /**
     * Authorize to Vault using AppRole method without secret ID.
     *
     * @param roleID The role ID
     * @return The {@link AuthResponse}
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default AuthResponse authAppRole(final String roleID) throws VaultConnectorException {
        return authAppRole(roleID, null);
    }

    /**
     * Authorize to Vault using AppRole method.
     *
     * @param roleID   The role ID
     * @param secretID The secret ID
     * @return The {@link AuthResponse}
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    AuthResponse authAppRole(final String roleID, final String secretID) throws VaultConnectorException;

    /**
     * Get authorization status.
     *
     * @return TRUE, if successfully authorized
     */
    boolean isAuthorized();

    /**
     * Retrieve any nodes content from Vault.
     *
     * @param key Secret identifier
     * @return Secret response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    SecretResponse read(final String key) throws VaultConnectorException;

    /**
     * List available nodes from Vault.
     *
     * @param path Root path to search
     * @return List of secret keys
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    List<String> list(final String path) throws VaultConnectorException;

    /**
     * Write simple value to Vault.
     *
     * @param key   Secret path
     * @param value Secret value
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default void write(final String key, final String value) throws VaultConnectorException {
        write(key, Collections.singletonMap("value", value));
    }

    /**
     * Write value to Vault.
     *
     * @param key  Secret path
     * @param data Secret content. Value must be be JSON serializable.
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default void write(final String key, final Map<String, Object> data) throws VaultConnectorException {
        write(key, data, null);
    }

    /**
     * Write value to Vault.
     *
     * @param key     Secret path
     * @param data    Secret content. Value must be be JSON serializable.
     * @param options Secret options (optional).
     * @throws VaultConnectorException on error
     * @since 0.8 {@code options} parameter added
     */
    void write(final String key, final Map<String, Object> data, final Map<String, Object> options)
        throws VaultConnectorException;

    /**
     * Delete key from Vault.
     *
     * @param key Secret path
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    void delete(final String key) throws VaultConnectorException;

    /**
     * Revoke given lease immediately.
     *
     * @param leaseID the lease ID
     * @throws VaultConnectorException on error
     */
    void revoke(final String leaseID) throws VaultConnectorException;

    /**
     * Renew lease with given ID.
     *
     * @param leaseID the lase ID
     * @return Renewed lease
     * @throws VaultConnectorException on error
     */
    default SecretResponse renew(final String leaseID) throws VaultConnectorException {
        return renew(leaseID, null);
    }

    /**
     * Renew lease with given ID.
     *
     * @param leaseID   the lase ID
     * @param increment number of seconds to extend lease time
     * @return Renewed lease
     * @throws VaultConnectorException on error
     */
    SecretResponse renew(final String leaseID, final Integer increment) throws VaultConnectorException;

    /**
     * Get client for KV v2 API.
     *
     * @return KV v2 client
     * @since 2.0.0
     */
    KV2Client kv2();

    /**
     * Get client for token API.
     *
     * @return Token client
     * @since 2.0.0
     */
    TokenClient token();

    /**
     * Get client for AppRole API.
     *
     * @return AppRole client
     * @since 2.0.0
     */
    AppRoleClient appRole();

    /**
     * Get client for transit API.
     *
     * @return Transit client
     * @since 2.0.0
     */
    TransitClient transit();

    /**
     * Get client for system API.
     *
     * @return System client
     * @since 2.0.0
     */
    SysClient sys();

    /**
     * Read credentials for database backends.
     *
     * @param role  the role name
     * @param mount mount point of the database backend
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default CredentialsResponse readDbCredentials(final String role, final String mount)
        throws VaultConnectorException {
        return (CredentialsResponse) read(mount + "/creds/" + role);
    }

}
