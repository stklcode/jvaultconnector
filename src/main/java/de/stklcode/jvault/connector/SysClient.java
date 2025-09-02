/*
 * Copyright 2016-2025 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.model.response.*;

import java.util.List;

/**
 * Sys client interface.
 * Provides methods to interact with Vault's system API.
 *
 * @since 2.0.0 extracted from {@link VaultConnector}
 */
public interface SysClient {

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
     * Get all available authentication backends.
     *
     * @return List of backends
     * @throws VaultConnectorException on error
     */
    List<AuthBackend> getAuthBackends() throws VaultConnectorException;

}
