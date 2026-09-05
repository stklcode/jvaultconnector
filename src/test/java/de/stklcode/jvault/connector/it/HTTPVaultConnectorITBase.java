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

package de.stklcode.jvault.connector.it;

import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.HTTPVaultConnectorBuilder;
import de.stklcode.jvault.connector.VaultConnector;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.response.SealResponse;
import de.stklcode.jvault.connector.test.VaultConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.io.FileUtils.copyDirectory;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Base class for HTTP Vault connector integration tests.
 * <p>
 * Starts Vault before running the tes class, see {@link #startVault(TestInfo, File)} and initializes a
 * matching connector for each test method, see {@link #initConnector(TestInfo)}.
 * <p>
 * Supported tags (class level):
 * <ul>
 *     <li>{@code tls} - start Vault with TLS certificate (default: plain HTTP)</li>
 *     <li>{@code sealed} - keep Vault sealed after startup (default: unseal before testing)</li>
 * </ul>
 *
 * @author Stefan Kalscheuer
 */
class HTTPVaultConnectorITBase {
    protected static String VAULT_VERSION = "2.1.0";  // The vault version this test is supposed to run against.
    protected static final String KEY1 = "+5n9tlpFnTNBAyutYQLT0o5J0AQ6Lt85u2KrEOan4gzb";
    protected static final String KEY2 = "4SSSIsllqY+c//t1M9IhBwzVSeBWgh0E0UbjacUD9/5g";
    protected static final String KEY3 = "O7AMGCi9Blt7gHHJdFjz1sHZHsUIOnvdFIV+AN2NwCxv";
    protected static final String TOKEN_ROOT = "30ug6wfy2wvlhhe5h7x0pbkx";
    protected static final String USER_VALID = "validUser";
    protected static final String PASS_VALID = "validPass";

    protected static VaultConfiguration vaultConfig;
    protected static Process vaultProcess;
    protected VaultConnector connector;

    /**
     * Start a local Vault instance.
     * Requires "vault" binary to be in current user's executable path. Not using MLock, so no extended rights required.
     *
     * @param testInfo Test info
     * @param tempDir  Temporary directory
     * @throws IOException Unable to create Vault data directory and process
     */
    @BeforeAll
    static void startVault(TestInfo testInfo, @TempDir File tempDir) throws IOException {
        // Override vault version if defined in sysenv.
        if (System.getenv("VAULT_VERSION") != null) {
            VAULT_VERSION = System.getenv("VAULT_VERSION");
            System.out.println("Vault version set to " + VAULT_VERSION);
        }

        // Determine, if TLS is required.
        boolean isTls = testInfo.getTags().contains("tls");

        // Initialize Vault.
        vaultConfig = initializeVault(tempDir, isTls);
    }

    @AfterAll
    static void stopVault() {
        if (vaultProcess != null) {
            vaultProcess.destroy();

            try {
                if (!vaultProcess.waitFor(5, TimeUnit.SECONDS)) {
                    vaultProcess.destroyForcibly();
                    vaultProcess.waitFor(5, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                vaultProcess.destroyForcibly();
                Thread.currentThread().interrupt();
            } finally {
                vaultProcess = null;
            }
        }
        vaultConfig = null;
    }

    /**
     * Initialize Vault connector for the running instance and unseal, if not configured.
     */
    @BeforeEach
    void initConnector(TestInfo testInfo) throws VaultConnectorException {
        if (vaultConfig == null) {
            throw new IllegalStateException("Vault not initialized");
        }

        // Initialize connector.
        HTTPVaultConnectorBuilder builder = HTTPVaultConnector.builder()
            .withHost(vaultConfig.getHost())
            .withPort(vaultConfig.getPort())
            .withTLS(vaultConfig.isTLS());
        if (vaultConfig.isTLS()) {
            builder.withTrustedCA(Paths.get(getResource("/tls/ca.pem")));
        }
        connector = builder.build();

        if (!testInfo.getTags().contains("sealed")) {
            // Unseal Vault and check result.
            SealResponse sealStatus = connector.sys().unseal(KEY1);
            assumeTrue(sealStatus != null, "Seal status could not be determined after startup");
            if (sealStatus.sealed()) {
                sealStatus = connector.sys().unseal(KEY2);
                assumeTrue(sealStatus != null, "Seal status could not be determined");
                assumeFalse(sealStatus.sealed(), "Vault is not unsealed");
                assumeTrue(sealStatus.initialized(), "Vault is not initialized"); // Initialized flag of Vault 0.11.2 (#20).
            }
        }
    }

    /**
     * Initialize Vault connector for the running instance and unseal, if not configured.
     */
    @AfterEach
    void closeConnector() throws Exception {
        if (connector != null) {
            try {
                connector.close();
            } finally {
                connector = null;
            }
        }

    }

    /**
     * Initialize Vault with resource datastore and generated configuration.
     *
     * @param dir Directory to place test data.
     * @param tls Use TLS.
     * @return Vault Configuration
     * @throws IllegalStateException on error
     */
    protected static VaultConfiguration initializeVault(File dir, boolean tls) throws IllegalStateException, IOException {
        File dataDir = new File(dir, "data");
        copyDirectory(new File(HTTPVaultConnectorITBase.class.getResource("/data_dir").getPath()), dataDir);

        // Generate vault local unencrypted configuration.
        VaultConfiguration config = new VaultConfiguration()
            .withHost("localhost")
            .withPort(getFreePort())
            .withDataLocation(dataDir.toPath())
            .disableMlock();

        // Enable TLS with custom certificate and key, if required.
        if (tls) {
            config.enableTLS()
                .withCert(getResource("/tls/server.pem"))
                .withKey(getResource("/tls/server.key"));
        }

        // Write configuration file.
        File configFile = new File(dir, "vault.conf");
        try {
            Files.writeString(configFile.toPath(), config.toString(), UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to generate config file", e);
        }

        // Start vault process.
        try {
            vaultProcess = new ProcessBuilder("vault", "server", "-config", configFile.toString())
                .directory(dir)
                .start();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to start vault. Make sure vault binary is in your executable path", e);
        }

        await().atMost(5, TimeUnit.SECONDS).until(() -> {
            try (InputStream stdout = vaultProcess.getInputStream();
                 InputStreamReader reader = new InputStreamReader(stdout);
                 BufferedReader br = new BufferedReader(reader)) {
                String line = br.readLine();
                while (line != null) {
                    if (line.contains("server started")) {
                        return true;
                    } else {
                        line = br.readLine();
                    }
                }

                return false;
            }
        });

        return config;
    }

    /**
     * Authenticate with root token.
     */
    protected void authRoot() {
        // Authenticate as valid user.
        assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
    }

    /**
     * Authenticate with user credentials.
     */
    protected void authUser() {
        assertDoesNotThrow(() -> connector.authUserPass(USER_VALID, PASS_VALID));
    }

    /**
     * Find and return a free TCP port.
     *
     * @return port number
     */
    private static Integer getFreePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);

            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to find a free TCP port", e);
        }
    }

    /**
     * Retrieve StackTrace from throwable as string
     *
     * @param th the throwable
     * @return the stack trace
     */
    protected static String stackTrace(final Throwable th) {
        StringWriter sw = new StringWriter();
        th.printStackTrace(new PrintWriter(sw, true));
        return sw.getBuffer().toString();
    }

    /**
     * Compare two version strings.
     *
     * @param version1 Version 1
     * @param version2 Version 2
     * @return negative value if version 1 is smaller than version2, positive value of version 1 is greater, 0 if equal
     */
    protected static int compareVersions(String version1, String version2) {
        int comparisonResult = 0;

        String[] version1Splits = version1.split("\\.");
        String[] version2Splits = version2.split("\\.");
        int maxLengthOfVersionSplits = Math.max(version1Splits.length, version2Splits.length);

        for (int i = 0; i < maxLengthOfVersionSplits; i++) {
            Integer v1 = i < version1Splits.length ? Integer.parseInt(version1Splits[i]) : 0;
            Integer v2 = i < version2Splits.length ? Integer.parseInt(version2Splits[i]) : 0;
            int compare = v1.compareTo(v2);
            if (compare != 0) {
                comparisonResult = compare;
                break;
            }
        }

        return comparisonResult;
    }

    private static String getResource(String path) {
        return HTTPVaultConnectorITBase.class.getResource(path).getPath();
    }
}
