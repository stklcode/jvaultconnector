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
import de.stklcode.jvault.connector.model.AppRole;
import de.stklcode.jvault.connector.model.AppRoleSecret;
import de.stklcode.jvault.connector.model.response.*;

import java.util.ArrayList;
import java.util.List;

/**
 * AppRole client interface.
 * Provides methods to interact with Vault's AppRole API.
 *
 * @since 2.0.0 extracted from {@link VaultConnector}
 */
public interface AppRoleClient {

    /**
     * Register a new AppRole role from given metamodel.
     *
     * @param role The role
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    boolean create(final AppRole role) throws VaultConnectorException;

    /**
     * Register new AppRole role with default policy.
     *
     * @param roleName The role name
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default boolean create(final String roleName) throws VaultConnectorException {
        return create(roleName, new ArrayList<>());
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
    default boolean create(final String roleName, final List<String> policies) throws VaultConnectorException {
        return create(roleName, policies, null);
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
    default boolean create(final String roleName, final String roleID) throws VaultConnectorException {
        return create(roleName, new ArrayList<>(), roleID);
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
    default boolean create(final String roleName, final List<String> policies, final String roleID)
        throws VaultConnectorException {
        return create(AppRole.builder(roleName).withTokenPolicies(policies).withId(roleID).build());
    }

    /**
     * Delete AppRole role from Vault.
     *
     * @param roleName The role name
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     */
    boolean delete(final String roleName) throws VaultConnectorException;

    /**
     * Lookup an AppRole role.
     *
     * @param roleName The role name
     * @return Result of the lookup
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    AppRoleResponse lookup(final String roleName) throws VaultConnectorException;

    /**
     * Retrieve ID for an AppRole role.
     *
     * @param roleName The role name
     * @return The role ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    String getRoleID(final String roleName) throws VaultConnectorException;

    /**
     * Set custom ID for an AppRole role.
     *
     * @param roleName The role name
     * @param roleID   The role ID
     * @return {@code true} on success
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    boolean setRoleID(final String roleName, final String roleID) throws VaultConnectorException;

    /**
     * Register new random generated AppRole secret.
     *
     * @param roleName The role name
     * @return The secret ID
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    default AppRoleSecretResponse createSecret(final String roleName) throws VaultConnectorException {
        return createSecret(roleName, new AppRoleSecret());
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
    default AppRoleSecretResponse createSecret(final String roleName, final String secretID)
        throws VaultConnectorException {
        return createSecret(roleName, new AppRoleSecret(secretID));
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
    AppRoleSecretResponse createSecret(final String roleName, final AppRoleSecret secret)
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
    AppRoleSecretResponse lookupSecret(final String roleName, final String secretID)
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
    boolean destroySecret(final String roleName, final String secretID) throws VaultConnectorException;

    /**
     * List existing (accessible) AppRole roles.
     *
     * @return List of roles
     * @throws VaultConnectorException on error
     */
    List<String> listRoles() throws VaultConnectorException;

    /**
     * List existing (accessible) secret IDs for AppRole role.
     *
     * @param roleName The role name
     * @return List of roles
     * @throws VaultConnectorException on error
     */
    List<String> listSecrets(final String roleName) throws VaultConnectorException;
}
