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

package de.stklcode.jvault.connector;

import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.Token;
import de.stklcode.jvault.connector.model.response.*;

import java.util.List;

/**
 * Vault Connector interface.
 * Provides methods to connect with Vault backend and handle secrets.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public interface VaultConnector {
    /**
     * Verify that vault connection is initialized.
     *
     * @return TRUE if correctly initialized
     */
    boolean init();

    /**
     * Reset authorization information.
     */
    void resetAuth();

    /**
     * Retrieve status of vault seal.
     *
     * @return Seal status
     */
    SealResponse sealStatus();

    /**
     * Seal vault.
     *
     * @return TRUE on success
     */
    boolean seal();

    /**
     * Unseal vault.
     *
     * @param key   A single master share key
     * @param reset Discard previously provided keys (optional)
     * @return TRUE on success
     */
    SealResponse unseal(final String key, final Boolean reset);

    /**
     * Unseal vault.
     *
     * @param key A single master share key
     * @return TRUE on success
     */
    default SealResponse unseal(final String key) {
        return unseal(key, null);
    }

    /**
     * Get all availale authentication backends.
     *
     * @return List of backends
     * @throws VaultConnectorException on error
     */
    List<AuthBackend> getAuthBackends() throws VaultConnectorException;

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
     * Authorize to Vault using AppID method.
     *
     * @param appID  The App ID
     * @param userID The User ID
     * @return TRUE on success
     * @throws VaultConnectorException on error
     */
    AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException;

    /**
     * Register new App-ID with policy.
     *
     * @param appID       The unique App-ID
     * @param policy      The policy to associate with
     * @param displayName Arbitrary name to display
     * @return TRUE on success
     * @throws VaultConnectorException on error
     */
    boolean registerAppId(final String appID, final String policy, final String displayName) throws VaultConnectorException;

    /**
     * Register User-ID with App-ID
     *
     * @param appID  The App-ID
     * @param userID The User-ID
     * @return TRUE on success
     * @throws VaultConnectorException on error
     */
    boolean registerUserId(final String appID, final String userID) throws VaultConnectorException;

    /**
     * Register new App-ID and User-ID at once.
     *
     * @param appID       The App-ID
     * @param policy      The policy to associate with
     * @param displayName Arbitrary name to display
     * @param userID      The User-ID
     * @return TRUE on success
     * @throws VaultConnectorException on error
     */
    default boolean registerAppUserId(final String appID, final String policy, final String displayName, final String userID) throws VaultConnectorException {
        return registerAppId(appID, policy, userID) && registerUserId(appID, userID);
    }

    /**
     * Get authorization status
     *
     * @return TRUE, if successfully authorized
     */
    boolean isAuthorized();

    /**
     * Retrieve secret form Vault.
     *
     * @param key Secret identifier
     * @return Secret response
     * @throws VaultConnectorException on error
     */
    SecretResponse readSecret(final String key) throws VaultConnectorException;

    /**
     * List available secrets from Vault.
     *
     * @param path Root path to search
     * @return List of secret keys
     * @throws VaultConnectorException on error
     */
    List<String> listSecrets(final String path) throws VaultConnectorException;

    /**
     * Write secret to Vault.
     *
     * @param key   Secret path
     * @param value Secret value
     * @return TRUE on success
     * @throws VaultConnectorException on error
     */
    boolean writeSecret(final String key, final String value) throws VaultConnectorException;

    /**
     * Delete secret from Vault.
     *
     * @param key Secret path
     * @return TRUE on succevss
     * @throws VaultConnectorException on error
     */
    boolean deleteSecret(final String key) throws VaultConnectorException;

    /**
     * Revoke given lease immediately.
     *
     * @param leaseID the lease ID
     * @return TRUE on success
     * @throws VaultConnectorException on error
     */
    boolean revoke(final String leaseID) throws VaultConnectorException;

    /**
     * Renew lease with given ID.
     *
     * @param leaseID the lase ID
     * @param seconds number of seconds to extend lease time
     * @return Renewed lease
     */
    VaultResponse renew(final String leaseID, final Integer seconds);

    /**
     * Create a new token.
     *
     * @param token the token
     * @return the result response
     * @throws VaultConnectorException on error
     */
    AuthResponse createToken(final Token token) throws VaultConnectorException;

    /**
     * Create a new token.
     *
     * @param token  the token
     * @param orphan create orphan token
     * @return the result response
     * @throws VaultConnectorException on error
     */
    AuthResponse createToken(final Token token, boolean orphan) throws VaultConnectorException;

    /**
     * Create a new token for specific role.
     *
     * @param token the token
     * @param role  the role name
     * @return the result response
     * @throws VaultConnectorException on error
     */
    AuthResponse createToken(final Token token, final String role) throws VaultConnectorException;
}
