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

package de.stklcode.jvault.connector.test;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Vault configuration String using builder pattern.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public class VaultConfiguration {
    private String host;
    private Integer port;
    private boolean disableTLS;
    private boolean disableMlock;
    private Path dataLocation;
    private String certFile;
    private String keyFile;

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

    public VaultConfiguration withCert(String certFile) {
        this.certFile = certFile;
        return this;
    }

    public VaultConfiguration withKey(String keyFile) {
        this.keyFile = keyFile;
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
        return "storage \"file\" {\n" +
            "  path = \"" + dataLocation + "\"\n" +
            "}\n" +
            "listener \"tcp\" {\n" +
            "  address = \"" + host + ":" + port + "\"\n" +
            ((disableTLS) ? "  tls_disable = 1\n" : "") +
            ((certFile != null) ? "  tls_cert_file = \"" + certFile + "\"\n" : "") +
            ((keyFile != null) ? "  tls_key_file = \"" + keyFile + "\"\n" : "") +
            "}\n" +
            ((disableMlock) ? "disable_mlock = true" : "");
    }
}
