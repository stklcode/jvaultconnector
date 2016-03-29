package de.stklcode.jvault.connector.factory;

import de.stklcode.jvault.connector.VaultConnector;

/**
 * Abstract Vault Connector Factory interface.
 * Provides builder pattern style factory for Vault connectors.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public abstract class VaultConnectorFactory {
    /**
     * Get Factory implementation for HTTP Vault Connector
     * @return  HTTP Connector Factory
     */
    public static HTTPVaultConnectorFactory httpFactory() {
        return new HTTPVaultConnectorFactory();
    }

    /**
     * Build command, produces connector after initialization.
     * @return  Vault Connector instance.
     */
    public abstract VaultConnector build();
}
