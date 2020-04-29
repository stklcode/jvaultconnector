/*
 * Copyright 2016-2020 Stefan Kalscheuer
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

import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.builder.HTTPVaultConnectorBuilder;
import de.stklcode.jvault.connector.exception.VaultConnectorException;

import javax.net.ssl.SSLContext;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

/**
 * Vault Connector Factory implementation for HTTP Vault connectors.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 * @deprecated As of 0.8.0 please refer to {@link de.stklcode.jvault.connector.builder.HTTPVaultConnectorBuilder} with identical API.
 */
@Deprecated
public final class HTTPVaultConnectorFactory extends VaultConnectorFactory {

    private final HTTPVaultConnectorBuilder delegate;

    /**
     * Default empty constructor.
     * Initializes factory with default values.
     */
    public HTTPVaultConnectorFactory() {
        delegate = new HTTPVaultConnectorBuilder();
    }

    /**
     * Set hostname (default: 127.0.0.1).
     *
     * @param host Hostname or IP address
     * @return self
     */
    public HTTPVaultConnectorFactory withHost(final String host) {
        delegate.withHost(host);
        return this;
    }

    /**
     * Set port (default: 8200).
     *
     * @param port Vault TCP port
     * @return self
     */
    public HTTPVaultConnectorFactory withPort(final Integer port) {
        delegate.withPort(port);
        return this;
    }

    /**
     * Set TLS usage (default: TRUE).
     *
     * @param useTLS use TLS or not
     * @return self
     */
    public HTTPVaultConnectorFactory withTLS(final boolean useTLS) {
        delegate.withTLS(useTLS);
        return this;
    }

    /**
     * Convenience Method for TLS usage (enabled by default).
     *
     * @return self
     */
    public HTTPVaultConnectorFactory withTLS() {
        return withTLS(true);
    }

    /**
     * Convenience Method for NOT using TLS.
     *
     * @return self
     */
    public HTTPVaultConnectorFactory withoutTLS() {
        return withTLS(false);
    }

    /**
     * Set API prefix. Default is "/v1/" and changes should not be necessary for current state of development.
     *
     * @param prefix Vault API prefix (default: "/v1/"
     * @return self
     */
    public HTTPVaultConnectorFactory withPrefix(final String prefix) {
        delegate.withPrefix(prefix);
        return this;
    }

    /**
     * Add a trusted CA certificate for HTTPS connections.
     *
     * @param cert path to certificate file
     * @return self
     * @throws VaultConnectorException on error
     * @since 0.4.0
     */
    public HTTPVaultConnectorFactory withTrustedCA(final Path cert) throws VaultConnectorException {
        delegate.withTrustedCA(cert);
        return this;
    }

    /**
     * Add a trusted CA certificate for HTTPS connections.
     *
     * @param cert path to certificate file
     * @return self
     * @since 0.8.0
     */
    public HTTPVaultConnectorFactory withTrustedCA(final X509Certificate cert) {
        delegate.withTrustedCA(cert);
        return this;
    }

    /**
     * Add a custom SSL context.
     * Overwrites certificates set by {@link #withTrustedCA}.
     *
     * @param sslContext the SSL context
     * @return self
     * @since 0.4.0
     * @deprecated As of 0.8.0 this is no longer supported, please use {@link #withTrustedCA(Path)} or {@link #withTrustedCA(X509Certificate)}.
     */
    public HTTPVaultConnectorFactory withSslContext(final SSLContext sslContext) {
        throw new UnsupportedOperationException("Use of deprecated method, please switch to withTrustedCA()");
    }

    /**
     * Set token for automatic authentication, using {@link #buildAndAuth()}.
     *
     * @param token Vault token
     * @return self
     * @since 0.6.0
     */
    public HTTPVaultConnectorFactory withToken(final String token) {
        delegate.withToken(token);
        return this;
    }

    /**
     * Build connector based on the {@code }VAULT_ADDR} and {@code VAULT_CACERT} (optional) environment variables.
     *
     * @return self
     * @throws VaultConnectorException if Vault address from environment variables is malformed
     * @since 0.6.0
     */
    public HTTPVaultConnectorFactory fromEnv() throws VaultConnectorException {
        delegate.fromEnv();
        return this;
    }

    /**
     * Define the number of retries to attempt on 5xx errors.
     *
     * @param numberOfRetries The number of retries to attempt on 5xx errors (default: 0)
     * @return self
     * @since 0.6.0
     */
    public HTTPVaultConnectorFactory withNumberOfRetries(final int numberOfRetries) {
        delegate.withNumberOfRetries(numberOfRetries);
        return this;
    }

    /**
     * Define a custom timeout for the HTTP connection.
     *
     * @param milliseconds Timeout value in milliseconds.
     * @return self
     * @since 0.6.0
     */
    public HTTPVaultConnectorFactory withTimeout(final int milliseconds) {
        delegate.withTimeout(milliseconds);
        return this;
    }

    @Override
    public HTTPVaultConnector build() {
        return delegate.build();
    }

    @Override
    public HTTPVaultConnector buildAndAuth() throws VaultConnectorException {
        return delegate.buildAndAuth();
    }
}
