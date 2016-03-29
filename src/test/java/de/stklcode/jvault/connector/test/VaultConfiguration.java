package de.stklcode.jvault.connector.test;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Vault configuration String using builder pattern.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class VaultConfiguration {
    private String host;
    private Integer port;
    private boolean disableTLS;
    private boolean disableMlock;
    private Path dataLocation;

    public VaultConfiguration() {
        this.disableTLS = true;
        this.disableMlock = false;
    }

    public VaultConfiguration withHost(String host) {
        this.host = host;
        return this;
    }

    public VaultConfiguration withPort(Integer port) {
        this.port = port;
        return this;
    }

    public VaultConfiguration enableTLS() {
        this.disableTLS = false;
        return this;
    }

    public VaultConfiguration disableMlock() {
        this.disableMlock = true;
        return this;
    }

    public VaultConfiguration withDataLocation(String dataLocation) {
        return withDataLocation(Paths.get(dataLocation));
    }

    public VaultConfiguration withDataLocation(Path dataLocation) {
        this.dataLocation = dataLocation;
        return this;
    }

    public String getHost() {
        return host;
    }

    public Integer getPort() {
        return port;
    }

    public boolean isTLS() {
        return !disableTLS;
    }

    @Override
    public String toString() {
        return  "backend \"file\" {\n" +
                "  path = \"" + dataLocation + "\"\n" +
                "}\n" +
                "listener \"tcp\" {\n" +
                "  address = \"" + host + ":" + port + "\"\n" +
                ((disableTLS) ? "  tls_disable = 1\n" : "") +
                "}\n" +
                ((disableMlock) ? "disable_mlock = true" : "");
    }
}