package de.stklcode.jvault.connector.factory;

import de.stklcode.jvault.connector.HTTPVaultConnector;

/**
 * Vault Connector Factory implementation for HTTP Vault connectors.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class HTTPVaultConnectorFactory extends VaultConnectorFactory {
    public static final String DEFAULT_HOST = "127.0.0.1";
    public static final Integer DEFAULT_PORT = 8200;
    public static final boolean DEFAULT_TLS = true;
    public static final String DEFAULT_PREFIX = "/v1/";

    private String host;
    private Integer port;
    private boolean tls;
    private String prefix;

    /**
     * Default empty constructor.
     * Initializes factory with default values.
     */
    public HTTPVaultConnectorFactory() {
        host = DEFAULT_HOST;
        port = DEFAULT_PORT;
        tls = DEFAULT_TLS;
        prefix = DEFAULT_PREFIX;
    }

    /**
     * Set hostname (default: 127.0.0.1)
     * @param host  Hostname or IP address
     * @return      self
     */
    public HTTPVaultConnectorFactory withHost(String host) {
        this.host = host;
        return this;
    }

    /**
     * Set port (default: 8200)
     * @param port  Vault TCP port
     * @return      self
     */
    public HTTPVaultConnectorFactory withPort(Integer port) {
        this.port = port;
        return this;
    }

    /**
     * Set TLS usage (default: TRUE)
     * @param useTLS    use TLS or not
     * @return          self
     */
    public HTTPVaultConnectorFactory withTLS(boolean useTLS) {
        this.tls = useTLS;
        return this;
    }

    /**
     * Convenience Method for TLS usage (enabled by default)
     * @return      self
     */
    public HTTPVaultConnectorFactory withTLS() {
        return withTLS(true);
    }

    /**
     * Convenience Method for NOT using TLS
     * @return      self
     */
    public HTTPVaultConnectorFactory withoutTLS() {
        return withTLS(false);
    }

    /**
     * Set API prefix. Default is "/v1/" and changes should not be necessary for current state of development.
     * @param prefix    Vault API prefix (default: "/v1/"
     * @return          self
     */
    public HTTPVaultConnectorFactory withPrefix(String prefix) {
        this.prefix = prefix;
        return this;
    }

    @Override
    public HTTPVaultConnector build() {
        return new HTTPVaultConnector(host, tls, port, prefix);
    }
}
