/*
 * Copyright 2016-2021 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.builder;

import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.exception.ConnectionException;
import de.stklcode.jvault.connector.exception.TlsException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Vault Connector Builder implementation for HTTP Vault connectors.
 *
 * @author Stefan Kalscheuer
 * @since 0.8.0
 */
public final class HTTPVaultConnectorBuilder implements VaultConnectorBuilder {
    private static final String ENV_VAULT_ADDR = "VAULT_ADDR";
    private static final String ENV_VAULT_CACERT = "VAULT_CACERT";
    private static final String ENV_VAULT_TOKEN = "VAULT_TOKEN";
    private static final String ENV_VAULT_MAX_RETRIES = "VAULT_MAX_RETRIES";

    public static final String DEFAULT_HOST = "127.0.0.1";
    public static final Integer DEFAULT_PORT = 8200;
    public static final boolean DEFAULT_TLS = true;
    public static final String DEFAULT_TLS_VERSION = "TLSv1.2";
    public static final String DEFAULT_PREFIX = "/v1/";
    public static final int DEFAULT_NUMBER_OF_RETRIES = 0;

    private String host;
    private Integer port;
    private boolean tls;
    private String tlsVersion;
    private String prefix;
    private X509Certificate trustedCA;
    private int numberOfRetries;
    private Integer timeout;
    private String token;

    /**
     * Default empty constructor.
     * Initializes factory with default values.
     */
    public HTTPVaultConnectorBuilder() {
        host = DEFAULT_HOST;
        port = DEFAULT_PORT;
        tls = DEFAULT_TLS;
        tlsVersion = DEFAULT_TLS_VERSION;
        prefix = DEFAULT_PREFIX;
        numberOfRetries = DEFAULT_NUMBER_OF_RETRIES;
    }

    /**
     * Set hostname (default: 127.0.0.1).
     *
     * @param host Hostname or IP address
     * @return self
     */
    public HTTPVaultConnectorBuilder withHost(final String host) {
        this.host = host;
        return this;
    }

    /**
     * Set port (default: 8200).
     *
     * @param port Vault TCP port
     * @return self
     */
    public HTTPVaultConnectorBuilder withPort(final Integer port) {
        this.port = port;
        return this;
    }

    /**
     * Set TLS usage (default: TRUE).
     *
     * @param useTLS use TLS or not
     * @return self
     */
    public HTTPVaultConnectorBuilder withTLS(final boolean useTLS) {
        this.tls = useTLS;
        return this;
    }

    /**
     * Set TLS usage (default: TRUE).
     *
     * @param useTLS  Use TLS or not.
     * @param version Supported TLS version ({@code TLSv1.2}, {@code TLSv1.1}, {@code TLSv1.0}, {@code TLS}).
     * @return self
     * @since 0.8 Added version parameter (#22).
     */
    public HTTPVaultConnectorBuilder withTLS(final boolean useTLS, final String version) {
        this.tls = useTLS;
        this.tlsVersion = version;
        return this;
    }

    /**
     * Convenience Method for TLS usage (enabled by default).
     *
     * @param version Supported TLS version ({@code TLSv1.2}, {@code TLSv1.1}, {@code TLSv1.0}, {@code TLS}).
     * @return self
     * @since 0.8 Added version parameter (#22).
     */
    public HTTPVaultConnectorBuilder withTLS(final String version) {
        return withTLS(true, version);
    }

    /**
     * Convenience Method for TLS usage (enabled by default).
     *
     * @return self
     */
    public HTTPVaultConnectorBuilder withTLS() {
        return withTLS(true);
    }

    /**
     * Convenience Method for NOT using TLS.
     *
     * @return self
     */
    public HTTPVaultConnectorBuilder withoutTLS() {
        return withTLS(false);
    }

    /**
     * Set API prefix. Default is "/v1/" and changes should not be necessary for current state of development.
     *
     * @param prefix Vault API prefix (default: "/v1/"
     * @return self
     */
    public HTTPVaultConnectorBuilder withPrefix(final String prefix) {
        this.prefix = prefix;
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
    public HTTPVaultConnectorBuilder withTrustedCA(final Path cert) throws VaultConnectorException {
        if (cert != null) {
            return withTrustedCA(certificateFromFile(cert));
        } else {
            this.trustedCA = null;
        }
        return this;
    }

    /**
     * Add a trusted CA certificate for HTTPS connections.
     *
     * @param cert path to certificate file
     * @return self
     * @since 0.8.0
     */
    public HTTPVaultConnectorBuilder withTrustedCA(final X509Certificate cert) {
        this.trustedCA = cert;
        return this;
    }

    /**
     * Set token for automatic authentication, using {@link #buildAndAuth()}.
     *
     * @param token Vault token
     * @return self
     * @since 0.6.0
     */
    public HTTPVaultConnectorBuilder withToken(final String token) {
        this.token = token;
        return this;
    }

    /**
     * Build connector based on the {@code }VAULT_ADDR} and {@code VAULT_CACERT} (optional) environment variables.
     *
     * @return self
     * @throws VaultConnectorException if Vault address from environment variables is malformed
     * @since 0.6.0
     */
    public HTTPVaultConnectorBuilder fromEnv() throws VaultConnectorException {
        /* Parse URL from environment variable */
        if (System.getenv(ENV_VAULT_ADDR) != null && !System.getenv(ENV_VAULT_ADDR).trim().isEmpty()) {
            try {
                var url = new URL(System.getenv(ENV_VAULT_ADDR));
                this.host = url.getHost();
                this.port = url.getPort();
                this.tls = url.getProtocol().equals("https");
            } catch (MalformedURLException e) {
                throw new ConnectionException("URL provided in environment variable malformed", e);
            }
        }

        /* Read number of retries */
        if (System.getenv(ENV_VAULT_MAX_RETRIES) != null) {
            try {
                numberOfRetries = Integer.parseInt(System.getenv(ENV_VAULT_MAX_RETRIES));
            } catch (NumberFormatException ignored) {
                /* Ignore malformed values. */
            }
        }

        /* Read token */
        token = System.getenv(ENV_VAULT_TOKEN);

        /* Parse certificate, if set */
        if (System.getenv(ENV_VAULT_CACERT) != null && !System.getenv(ENV_VAULT_CACERT).trim().isEmpty()) {
            return withTrustedCA(Paths.get(System.getenv(ENV_VAULT_CACERT)));
        }
        return this;
    }

    /**
     * Define the number of retries to attempt on 5xx errors.
     *
     * @param numberOfRetries The number of retries to attempt on 5xx errors (default: 0)
     * @return self
     * @since 0.6.0
     */
    public HTTPVaultConnectorBuilder withNumberOfRetries(final int numberOfRetries) {
        this.numberOfRetries = numberOfRetries;
        return this;
    }

    /**
     * Define a custom timeout for the HTTP connection.
     *
     * @param milliseconds Timeout value in milliseconds.
     * @return self
     * @since 0.6.0
     */
    public HTTPVaultConnectorBuilder withTimeout(final int milliseconds) {
        this.timeout = milliseconds;
        return this;
    }

    @Override
    public HTTPVaultConnector build() {
        return new HTTPVaultConnector(host, tls, tlsVersion, port, prefix, trustedCA, numberOfRetries, timeout);
    }

    @Override
    public HTTPVaultConnector buildAndAuth() throws VaultConnectorException {
        if (token == null) {
            throw new ConnectionException("No vault token provided, unable to authenticate.");
        }
        HTTPVaultConnector con = build();
        con.authToken(token);
        return con;
    }

    /**
     * Read given certificate file to X.509 certificate.
     *
     * @param certFile Path to certificate file
     * @return X.509 Certificate object
     * @throws TlsException on error
     * @since 0.4.0
     */
    private X509Certificate certificateFromFile(final Path certFile) throws TlsException {
        try (var is = Files.newInputStream(certFile)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (IOException | CertificateException e) {
            throw new TlsException("Unable to read certificate.", e);
        }
    }
}
