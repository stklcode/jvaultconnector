/*
 * Copyright 2016-2017 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.factory;

import de.stklcode.jvault.connector.VaultConnector;
import de.stklcode.jvault.connector.exception.VaultConnectorException;

/**
 * Abstract Vault Connector Factory interface.
 * Provides builder pattern style factory for Vault connectors.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public abstract class VaultConnectorFactory {
    /**
     * Get Factory implementation for HTTP Vault Connector.
     *
     * @return HTTP Connector Factory
     */
    public static HTTPVaultConnectorFactory httpFactory() {
        return new HTTPVaultConnectorFactory();
    }

    /**
     * Build command, produces connector after initialization.
     *
     * @return Vault Connector instance.
     */
    public abstract VaultConnector build();

    /**
     * Build connector and authenticate with token set in factory or from environment.
     *
     * @return Authenticated Vault connector instance.
     * @throws VaultConnectorException if authentication failed
     * @since 0.6.0
     */
    public abstract VaultConnector buildAndAuth() throws VaultConnectorException;
}
