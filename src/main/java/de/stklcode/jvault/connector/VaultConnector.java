/*
 * Copyright 2016-2019 Stefan Kalscheuer
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

import de.stklcode.jvault.connector.exception.InvalidRequestException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.*;
import de.stklcode.jvault.connector.model.response.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Vault Connector interface.
 * Provides methods to connect with Vault backend and handle secrets.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public interface VaultConnector extends AutoCloseable, Serializable {
    /**
     * Default sub-path for Vault secrets.
     */
    String PATH_SECRET = "secret";

    /**
     * Reset authorization information.
     */
    void resetAuth();

    /**
     * Retrieve status of vault seal.
     *
     * @return Seal status
     * @throws VaultConnectorException on error
     */
    SealResponse sealStatus() throws VaultConnectorException;

    /**
     * Seal vault.
     *
     * @throws VaultConnectorException on error
     */
    void seal() throws VaultConnectorException;

    /**
     * Unseal vault.
     *
     * @param key   A single master share key
     * @param reset Discard previously provided keys (optional)
     * @return Response with seal status
     * @throws VaultConnectorException on error
     */
    SealResponse unseal(final String key, final Boolean reset) throws VaultConnectorException;

    /**
     * Unseal vault.
     *
     * @param key A single master share key
     * @return Response with seal status
     * @throws VaultConnectorException on error
     */
    default SealResponse unseal(final String key) throws VaultConnectorException {
        return unseal(key, null);
    }

    /**
     * Query server health information.
     *
     * @return Health information.
     * @throws VaultConnectorException on error
     * @since 0.7.0
     */
    HealthResponse getHealth() throws VaultConnectorException;

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
     * @return The {@link AuthResponse}
     * @throws VaultConnectorException on error
     * @deprecated As of Vault 0.6.1 App-ID is superseded by AppRole. Consider using {@link #authAppRole} instead.
     */
    @Deprecated
    AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException;

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
     * Register new App-ID with policy.
     *
     * @param appID       The unique App-ID
     * @param policy      The policy to associate with
     * @param displayName Arbitrary name to display
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @deprecated As of Vault 0.6.1 App-ID is superseded by AppRole. Consider using {@link #createAppRole} instead.
     */
    @Deprecated
    boolean registerAppId(final String appID, final String policy, final String displayName)
            throws VaultConnectorException;

    /**
     * Register a new AppRole role from given metamodel.
     *
     * @param role The role
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    boolean createAppRole(final AppRole role) throws VaultConnectorException;

    /**
     * Register new AppRole role with default policy.
     *
     * @param roleName The role name
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default boolean createAppRole(final String roleName) throws VaultConnectorException {
        return createAppRole(roleName, new ArrayList<>());
    }

    /**
     * Register new AppRole role with policies.
     *
     * @param roleName The role name
     * @param policies The policies to associate with
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default boolean createAppRole(final String roleName, final List<String> policies) throws VaultConnectorException {
        return createAppRole(roleName, policies, null);
    }

    /**
     * Register new AppRole role with default policy and custom ID.
     *
     * @param roleName The role name
     * @param roleID   A custom role ID
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default boolean createAppRole(final String roleName, final String roleID) throws VaultConnectorException {
        return createAppRole(roleName, new ArrayList<>(), roleID);
    }

    /**
     * Register new AppRole role with policies and custom ID.
     *
     * @param roleName The role name
     * @param policies The policies to associate with
     * @param roleID   A custom role ID
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default boolean createAppRole(final String roleName, final List<String> policies, final String roleID)
            throws VaultConnectorException {
        return createAppRole(new AppRoleBuilder(roleName).withPolicies(policies).withId(roleID).build());
    }

    /**
     * Delete AppRole role from Vault.
     *
     * @param roleName The role anme
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     */
    boolean deleteAppRole(final String roleName) throws VaultConnectorException;

    /**
     * Lookup an AppRole role.
     *
     * @param roleName The role name
     * @return Result of the lookup
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    AppRoleResponse lookupAppRole(final String roleName) throws VaultConnectorException;

    /**
     * Retrieve ID for an AppRole role.
     *
     * @param roleName The role name
     * @return The role ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    String getAppRoleID(final String roleName) throws VaultConnectorException;

    /**
     * Set custom ID for an AppRole role.
     *
     * @param roleName The role name
     * @param roleID   The role ID
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    boolean setAppRoleID(final String roleName, final String roleID) throws VaultConnectorException;

    /**
     * Register new random generated AppRole secret.
     *
     * @param roleName The role name
     * @return The secret ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default AppRoleSecretResponse createAppRoleSecret(final String roleName) throws VaultConnectorException {
        return createAppRoleSecret(roleName, new AppRoleSecret());
    }

    /**
     * Register new AppRole secret with custom ID.
     *
     * @param roleName The role name
     * @param secretID A custom secret ID
     * @return The secret ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default AppRoleSecretResponse createAppRoleSecret(final String roleName, final String secretID)
            throws VaultConnectorException {
        return createAppRoleSecret(roleName, new AppRoleSecret(secretID));
    }

    /**
     * Register new AppRole secret with custom ID.
     *
     * @param roleName The role name
     * @param secret   The secret meta object
     * @return The secret ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    AppRoleSecretResponse createAppRoleSecret(final String roleName, final AppRoleSecret secret)
            throws VaultConnectorException;

    /**
     * Lookup an AppRole secret.
     *
     * @param roleName The role name
     * @param secretID The secret ID
     * @return Result of the lookup
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    AppRoleSecretResponse lookupAppRoleSecret(final String roleName, final String secretID)
            throws VaultConnectorException;

    /**
     * Destroy an AppRole secret.
     *
     * @param roleName The role name
     * @param secretID The secret meta object
     * @return The secret ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    boolean destroyAppRoleSecret(final String roleName, final String secretID) throws VaultConnectorException;

    /**
     * List existing (accessible) AppRole roles.
     *
     * @return List of roles
     * @throws VaultConnectorException on error
     */
    List<String> listAppRoles() throws VaultConnectorException;

    /**
     * List existing (accessible) secret IDs for AppRole role.
     *
     * @param roleName The role name
     * @return List of roles
     * @throws VaultConnectorException on error
     */
    List<String> listAppRoleSecrets(final String roleName) throws VaultConnectorException;

    /**
     * Register User-ID with App-ID.
     *
     * @param appID  The App-ID
     * @param userID The User-ID
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @deprecated As of Vault 0.6.1 App-ID is superseded by AppRole.
     * Consider using {@link #createAppRoleSecret} instead.
     */
    @Deprecated
    boolean registerUserId(final String appID, final String userID) throws VaultConnectorException;

    /**
     * Register new App-ID and User-ID at once.
     *
     * @param appID       The App-ID
     * @param policy      The policy to associate with
     * @param displayName Arbitrary name to display
     * @param userID      The User-ID
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @deprecated As of Vault 0.6.1 App-ID is superseded by AppRole.
     */
    @Deprecated
    default boolean registerAppUserId(final String appID,
                                      final String policy,
                                      final String displayName,
                                      final String userID) throws VaultConnectorException {
        return registerAppId(appID, policy, userID) && registerUserId(appID, userID);
    }

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
     * Retrieve secret from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to key.
     *
     * @param key Secret identifier
     * @return Secret response
     * @throws VaultConnectorException on error
     */
    default SecretResponse readSecret(final String key) throws VaultConnectorException {
        return read(PATH_SECRET + "/" + key);
    }

    /**
     * Retrieve the latest secret data for specific version from Vault.
     * <br>
     * Prefix "secret/data" is automatically added to key.
     * Only available for KV v2 secrets.
     *
     * @param key Secret identifier
     * @return Secret response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretResponse readSecretData(final String key) throws VaultConnectorException {
        return readSecretVersion(key, null);
    }

    /**
     * Retrieve the latest secret data for specific version from Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mountpoint (without leading or trailing slash).
     * @param key   Secret identifier
     * @return Secret response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretResponse readSecretData(final String mount, final String key) throws VaultConnectorException {
        return readSecretVersion(mount, key, null);
    }

    /**
     * Write secret to Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     * Only available for KV v2 secrets.
     *
     * @param key  Secret identifier.
     * @param data Secret content. Value must be be JSON serializable.
     * @return Metadata for the created/updated secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretVersionResponse writeSecretData(final String key, final Map<String, Object> data) throws VaultConnectorException {
        return writeSecretData(PATH_SECRET, key, data, null);
    }

    /**
     * Write secret to Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is written here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mountpoint (without leading or trailing slash).
     * @param key   Secret identifier
     * @param data  Secret content. Value must be be JSON serializable.
     * @return Metadata for the created/updated secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretVersionResponse writeSecretData(final String mount, final String key, final Map<String, Object> data) throws VaultConnectorException {
        return writeSecretData(mount, key, data, null);
    }

    /**
     * Write secret to Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is written here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mountpoint (without leading or trailing slash).
     * @param key   Secret identifier
     * @param data  Secret content. Value must be be JSON serializable.
     * @param cas   Use Check-And-Set operation, i.e. only allow writing if current version matches this value.
     * @return Metadata for the created/updated secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    SecretVersionResponse writeSecretData(final String mount, final String key, final Map<String, Object> data, final Integer cas) throws VaultConnectorException;

    /**
     * Retrieve secret data from Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param key     Secret identifier
     * @param version Version to read. If {@code null} or zero, the latest version will be returned.
     * @return Secret response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretResponse readSecretVersion(final String key, final Integer version) throws VaultConnectorException {
        return readSecretVersion(PATH_SECRET, key, version);
    }

    /**
     * Retrieve secret data from Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param mount   Secret store mountpoint (without leading or trailing slash).
     * @param key     Secret identifier
     * @param version Version to read. If {@code null} or zero, the latest version will be returned.
     * @return Secret responsef
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    SecretResponse readSecretVersion(final String mount, final String key, final Integer version) throws VaultConnectorException;

    /**
     * Retrieve secret metadata from Vault.
     * Path {@code secret/metadata/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param key Secret identifier
     * @return Metadata response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default MetadataResponse readSecretMetadata(final String key) throws VaultConnectorException {
        return readSecretMetadata(PATH_SECRET, key);
    }

    /**
     * Update secret metadata.
     * <br>
     * Path {@code secret/metadata/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param key         Secret identifier
     * @param maxVersions Maximum number of versions (fallback to backend default if {@code null})
     * @param casRequired Specify if Check-And-Set is required for this secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default void updateSecretMetadata(final String key, final Integer maxVersions, final boolean casRequired) throws VaultConnectorException {
        updateSecretMetadata(PATH_SECRET, key, maxVersions, casRequired);
    }

    /**
     * Retrieve secret metadata from Vault.
     * <br>
     * Path {@code <mount>/metadata/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mountpoint (without leading or trailing slash).
     * @param key   Secret identifier
     * @return Metadata response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    MetadataResponse readSecretMetadata(final String mount, final String key) throws VaultConnectorException;

    /**
     * Update secret metadata.
     * <br>
     * Path {@code <mount>/metadata/<key>} is written here.
     * Only available for KV v2 secrets.
     *
     * @param mount       Secret store mountpoint (without leading or trailing slash).
     * @param key         Secret identifier
     * @param maxVersions Maximum number of versions (fallback to backend default if {@code null})
     * @param casRequired Specify if Check-And-Set is required for this secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void updateSecretMetadata(final String mount, final String key, final Integer maxVersions, final boolean casRequired) throws VaultConnectorException;

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
     * List available secrets from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     *
     * @param path Root path to search
     * @return List of secret keys
     * @throws VaultConnectorException on error
     */
    default List<String> listSecrets(final String path) throws VaultConnectorException {
        return list(PATH_SECRET + "/" + path);
    }

    /**
     * Write simple value to Vault.
     *
     * @param key   Secret path
     * @param value Secret value
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default void write(final String key, final String value) throws VaultConnectorException {
        Map<String, Object> param = new HashMap<>();
        param.put("value", value);
        write(key, param);
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
    void write(final String key, final Map<String, Object> data, final Map<String, Object> options) throws VaultConnectorException;

    /**
     * Write secret to Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     *
     * @param key   Secret path
     * @param value Secret value
     * @throws VaultConnectorException on error
     */
    default void writeSecret(final String key, final String value) throws VaultConnectorException {
        Map<String, Object> param = new HashMap<>();
        param.put("value", value);
        writeSecret(key, param);
    }

    /**
     * Write secret to Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     *
     * @param key  Secret path
     * @param data Secret content. Value must be be JSON serializable.
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default void writeSecret(final String key, final Map<String, Object> data) throws VaultConnectorException {
        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("Secret path must not be empty.");
        }
        write(PATH_SECRET + "/" + key, data);
    }

    /**
     * Delete key from Vault.
     *
     * @param key Secret path
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    void delete(final String key) throws VaultConnectorException;

    /**
     * Delete secret from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     *
     * @param key Secret path
     * @throws VaultConnectorException on error
     */
    default void deleteSecret(final String key) throws VaultConnectorException {
        delete(PATH_SECRET + "/" + key);
    }

    /**
     * Delete latest version of a secret from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path. Only available for KV v2 stores.
     *
     * @param key Secret path.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default void deleteLatestSecretVersion(final String key) throws VaultConnectorException {
        deleteLatestSecretVersion(PATH_SECRET, key);
    }

    /**
     * Delete latest version of a secret from Vault.
     * <br>
     * Only available for KV v2 stores.
     *
     * @param mount Secret store mountpoint (without leading or trailing slash).
     * @param key   Secret path.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void deleteLatestSecretVersion(final String mount, final String key) throws VaultConnectorException;

    /**
     * Delete latest version of a secret from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     * Only available for KV v2 stores.
     *
     * @param key Secret path.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default void deleteAllSecretVersions(final String key) throws VaultConnectorException {
        deleteAllSecretVersions(PATH_SECRET, key);
    }

    /**
     * Delete latest version of a secret from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     * Only available for KV v2 stores.
     *
     * @param mount Secret store mountpoint (without leading or trailing slash).
     * @param key   Secret path.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void deleteAllSecretVersions(final String mount, final String key) throws VaultConnectorException;

    /**
     * Delete secret versions from Vault.
     * <br>
     * Only available for KV v2 stores.
     *
     * @param key      Secret path.
     * @param versions Versions of the secret to delete.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default void deleteSecretVersions(final String key, final int... versions) throws VaultConnectorException {
        deleteSecretVersions(PATH_SECRET, key, versions);
    }

    /**
     * Delete secret versions from Vault.
     * <br>
     * Only available for KV v2 stores.
     *
     * @param mount    Secret store mountpoint (without leading or trailing slash).
     * @param key      Secret path.
     * @param versions Versions of the secret to delete.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void deleteSecretVersions(final String mount, final String key, final int... versions) throws VaultConnectorException;

    /**
     * Undelete (restore) secret versions from Vault.
     * Only available for KV v2 stores.
     *
     * @param key      Secret path.
     * @param versions Versions of the secret to undelete.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default void undeleteSecretVersions(final String key, final int... versions) throws VaultConnectorException {
        undeleteSecretVersions(PATH_SECRET, key, versions);
    }

    /**
     * Undelete (restore) secret versions from Vault.
     * Only available for KV v2 stores.
     *
     * @param mount    Secret store mountpoint (without leading or trailing slash).
     * @param key      Secret path.
     * @param versions Versions of the secret to undelete.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void undeleteSecretVersions(final String mount, final String key, final int... versions) throws VaultConnectorException;

    /**
     * Destroy secret versions from Vault.
     * Only available for KV v2 stores.
     *
     * @param key      Secret path.
     * @param versions Versions of the secret to destroy.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default void destroySecretVersions(final String key, final int... versions) throws VaultConnectorException {
        destroySecretVersions(PATH_SECRET, key, versions);
    }

    /**
     * Destroy secret versions from Vault.
     * Only available for KV v2 stores.
     *
     * @param mount    Secret store mountpoint (without leading or trailing slash).
     * @param key      Secret path.
     * @param versions Versions of the secret to destroy.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void destroySecretVersions(final String mount, final String key, final int... versions) throws VaultConnectorException;

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

    /**
     * Lookup token information.
     *
     * @param token the token
     * @return the result response
     * @throws VaultConnectorException on error
     */
    TokenResponse lookupToken(final String token) throws VaultConnectorException;

    /**
     * Create a new or update an existing token role.
     *
     * @param role the role entity (name must be set)
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    default boolean createOrUpdateTokenRole(final TokenRole role) throws VaultConnectorException {
        return createOrUpdateTokenRole(role.getName(), role);
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
    boolean createOrUpdateTokenRole(final String name, final TokenRole role) throws VaultConnectorException;

    /**
     * Lookup token information.
     *
     * @param name the role name
     * @return the result response
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    TokenRoleResponse readTokenRole(final String name) throws VaultConnectorException;

    /**
     * List available token roles from Vault.
     *
     * @return List of token roles
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    List<String> listTokenRoles() throws VaultConnectorException;

    /**
     * Delete a token role.
     *
     * @param name the role name to delete
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.9
     */
    boolean deleteTokenRole(final String name) throws VaultConnectorException;

    /**
     * Read credentials for MySQL backend at default mount point.
     *
     * @param role the role name
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default CredentialsResponse readMySqlCredentials(final String role) throws VaultConnectorException {
        return readDbCredentials(role, "mysql");
    }

    /**
     * Read credentials for PostgreSQL backend at default mount point.
     *
     * @param role the role name
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default CredentialsResponse readPostgreSqlCredentials(final String role) throws VaultConnectorException {
        return readDbCredentials(role, "postgresql");
    }

    /**
     * Read credentials for MSSQL backend at default mount point.
     *
     * @param role the role name
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default CredentialsResponse readMsSqlCredentials(final String role) throws VaultConnectorException {
        return readDbCredentials(role, "mssql");
    }

    /**
     * Read credentials for MSSQL backend at default mount point.
     *
     * @param role the role name
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default CredentialsResponse readMongoDbCredentials(final String role) throws VaultConnectorException {
        return readDbCredentials(role, "mongodb");
    }

    /**
     * Read credentials for SQL backends.
     *
     * @param role  the role name
     * @param mount mount point of the SQL backend
     * @return the credentials response
     * @throws VaultConnectorException on error
     * @since 0.5.0
     */
    default CredentialsResponse readDbCredentials(final String role, final String mount)
            throws VaultConnectorException {
        return (CredentialsResponse) read(mount + "/creds/" + role);
    }
}
