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
import de.stklcode.jvault.connector.model.response.MetadataResponse;
import de.stklcode.jvault.connector.model.response.SecretResponse;
import de.stklcode.jvault.connector.model.response.SecretVersionResponse;

import java.util.Map;

/**
 * KV v2 client interface.
 * Provides methods to interact with Vault's KV v2 API.
 *
 * @since 2.0.0 extracted from {@link VaultConnector}
 */
public interface KV2Client {

    /**
     * Retrieve the latest secret data for specific version from Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mount point (without leading or trailing slash).
     * @param key   Secret identifier
     * @return Secret response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretResponse readData(final String mount, final String key) throws VaultConnectorException {
        return readVersion(mount, key, null);
    }

    /**
     * Write secret to Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is written here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mount point (without leading or trailing slash).
     * @param key   Secret identifier
     * @param data  Secret content. Value must be be JSON serializable.
     * @return Metadata for the created/updated secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    default SecretVersionResponse writeData(final String mount,
                                            final String key,
                                            final Map<String, Object> data) throws VaultConnectorException {
        return writeData(mount, key, data, null);
    }

    /**
     * Write secret to Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is written here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mount point (without leading or trailing slash).
     * @param key   Secret identifier
     * @param data  Secret content. Value must be be JSON serializable.
     * @param cas   Use Check-And-Set operation, i.e. only allow writing if current version matches this value.
     * @return Metadata for the created/updated secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    SecretVersionResponse writeData(final String mount,
                                    final String key,
                                    final Map<String, Object> data,
                                    final Integer cas) throws VaultConnectorException;

    /**
     * Retrieve secret data from Vault.
     * <br>
     * Path {@code <mount>/data/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param mount   Secret store mount point (without leading or trailing slash).
     * @param key     Secret identifier
     * @param version Version to read. If {@code null} or zero, the latest version will be returned.
     * @return Secret response.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    SecretResponse readVersion(final String mount, final String key, final Integer version)
        throws VaultConnectorException;

    /**
     * Retrieve secret metadata from Vault.
     * <br>
     * Path {@code <mount>/metadata/<key>} is read here.
     * Only available for KV v2 secrets.
     *
     * @param mount Secret store mount point (without leading or trailing slash).
     * @param key   Secret identifier
     * @return Metadata response
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    MetadataResponse readMetadata(final String mount, final String key) throws VaultConnectorException;

    /**
     * Update secret metadata.
     * <br>
     * Path {@code <mount>/metadata/<key>} is written here.
     * Only available for KV v2 secrets.
     *
     * @param mount       Secret store mount point (without leading or trailing slash).
     * @param key         Secret identifier
     * @param maxVersions Maximum number of versions (fallback to backend default if {@code null})
     * @param casRequired Specify if Check-And-Set is required for this secret.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void updateMetadata(final String mount,
                        final String key,
                        final Integer maxVersions,
                        final boolean casRequired) throws VaultConnectorException;

    /**
     * Delete latest version of a secret from Vault.
     * <br>
     * Only available for KV v2 stores.
     *
     * @param mount Secret store mount point (without leading or trailing slash).
     * @param key   Secret path.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void deleteLatestVersion(final String mount, final String key) throws VaultConnectorException;

    /**
     * Delete latest version of a secret from Vault.
     * <br>
     * Prefix {@code secret/} is automatically added to path.
     * Only available for KV v2 stores.
     *
     * @param mount Secret store mount point (without leading or trailing slash).
     * @param key   Secret path.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void deleteAllVersions(final String mount, final String key) throws VaultConnectorException;

    /**
     * Delete secret versions from Vault.
     * <br>
     * Only available for KV v2 stores.
     *
     * @param mount    Secret store mount point (without leading or trailing slash).
     * @param key      Secret path.
     * @param versions Versions of the secret to delete.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void deleteVersions(final String mount, final String key, final int... versions)
        throws VaultConnectorException;

    /**
     * Undelete (restore) secret versions from Vault.
     * Only available for KV v2 stores.
     *
     * @param mount    Secret store mount point (without leading or trailing slash).
     * @param key      Secret path.
     * @param versions Versions of the secret to undelete.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void undeleteVersions(final String mount, final String key, final int... versions)
        throws VaultConnectorException;

    /**
     * Destroy secret versions from Vault.
     * Only available for KV v2 stores.
     *
     * @param mount    Secret store mount point (without leading or trailing slash).
     * @param key      Secret path.
     * @param versions Versions of the secret to destroy.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    void destroyVersions(final String mount, final String key, final int... versions)
        throws VaultConnectorException;
}
