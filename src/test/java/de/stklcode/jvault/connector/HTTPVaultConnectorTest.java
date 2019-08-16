/*
 * Copyright 2016-2019 Stefan Kalscheuer
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

import de.stklcode.jvault.connector.builder.HTTPVaultConnectorBuilder;
import de.stklcode.jvault.connector.builder.VaultConnectorBuilder;
import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.AppRole;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.Token;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.test.Credentials;
import de.stklcode.jvault.connector.test.VaultConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.apache.commons.io.FileUtils.copyDirectory;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.junit.MatcherAssume.assumeThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * JUnit test for HTTP Vault connector.
 * This test requires Vault binary in executable Path as it instantiates a real Vault server on given test data.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@Tag("online")
public class HTTPVaultConnectorTest {
    private static String VAULT_VERSION = "1.2.2";  // the vault version this test is supposed to run against
    private static final String KEY1 = "E38bkCm0VhUvpdCKGQpcohhD9XmcHJ/2hreOSY019Lho";
    private static final String KEY2 = "O5OHwDleY3IiPdgw61cgHlhsrEm6tVJkrxhF6QAnILd1";
    private static final String KEY3 = "mw7Bm3nbt/UWa/juDjjL2EPQ04kiJ0saC5JEXwJvXYsB";
    private static final String TOKEN_ROOT = "30ug6wfy2wvlhhe5h7x0pbkx";
    private static final String USER_VALID = "validUser";
    private static final String PASS_VALID = "validPass";

    private Process vaultProcess;
    private VaultConnector connector;

    @BeforeAll
    public static void init() {
        // Override vault version if defined in sysenv.
        if (System.getenv("VAULT_VERSION") != null) {
            VAULT_VERSION = System.getenv("VAULT_VERSION");
            System.out.println("Vault version set to " + VAULT_VERSION);
        }
    }

    /**
     * Initialize Vault instance with generated configuration and provided file backend.
     * Requires "vault" binary to be in current user's executable path. Not using MLock, so no extended rights required.
     */
    @BeforeEach
    public void setUp(TestInfo testInfo, @TempDir File tempDir) throws VaultConnectorException, IOException {
        /* Determine, if TLS is required */
        boolean isTls = testInfo.getTags().contains("tls");

        /* Initialize Vault */
        VaultConfiguration config = initializeVault(tempDir, isTls);
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        /* Initialize connector */
        HTTPVaultConnectorBuilder builder = VaultConnectorBuilder.http()
                .withHost(config.getHost())
                .withPort(config.getPort())
                .withTLS(isTls);
        if (isTls) {
            builder.withTrustedCA(Paths.get(getClass().getResource("/tls/ca.pem").getPath()));
        }
        connector = builder.build();

        /* Unseal Vault and check result */
        SealResponse sealStatus = connector.unseal(KEY1);
        assumeTrue(sealStatus != null, "Seal status could not be determined after startup");
        assumeTrue(sealStatus.isSealed(), "Vault is not sealed after startup");
        sealStatus = connector.unseal(KEY2);
        assumeTrue(sealStatus != null, "Seal status could not be determined");
        assumeFalse(sealStatus.isSealed(), "Vault is not unsealed");
        assumeTrue(sealStatus.isInitialized(), "Vault is not initialized"); // Initialized flag of Vault 0.11.2 (#20).
    }

    @AfterEach
    public void tearDown() {
        if (vaultProcess != null && vaultProcess.isAlive())
            vaultProcess.destroy();
    }

    @Nested
    @DisplayName("Read/Write Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class ReadWriteTests {
        private static final String SECRET_PATH = "userstore";
        private static final String SECRET_KEY = "foo";
        private static final String SECRET_VALUE = "bar";
        private static final String SECRET_KEY_JSON = "json";
        private static final String SECRET_KEY_COMPLEX = "complex";

        /**
         * Test reading of secrets.
         */
        @Test
        @Order(10)
        @DisplayName("Read secrets")
        @SuppressWarnings("deprecation")
        public void readSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            /* Try to read path user has no permission to read */
            SecretResponse res = null;
            final String invalidPath = "invalid/path";
            try {
                res = connector.readSecret(invalidPath);
                fail("Invalid secret path successfully read.");
            } catch (VaultConnectorException e) {
                assertThat(e, instanceOf(PermissionDeniedException.class));
                /* Assert that the exception does not reveal secret or credentials */
                assertThat(stackTrace(e), not(stringContainsInOrder(invalidPath)));
                assertThat(stackTrace(e), not(stringContainsInOrder(USER_VALID)));
                assertThat(stackTrace(e), not(stringContainsInOrder(PASS_VALID)));
                assertThat(stackTrace(e), not(matchesPattern("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")));
            }

            /* Try to read accessible path with known value */
            try {
                res = connector.readSecret(SECRET_PATH + "/" + SECRET_KEY);
                assertThat("Known secret returned invalid value.", res.getValue(), is(SECRET_VALUE));
            } catch (VaultConnectorException e) {
                fail("Valid secret path could not be read: " + e.getMessage());
            }

            /* Try to read accessible path with JSON value */
            try {
                res = connector.readSecret(SECRET_PATH + "/" + SECRET_KEY_JSON);
                assertThat("Known secret returned null value.", res.getValue(), notNullValue());
            } catch (VaultConnectorException e) {
                fail("Valid secret path could not be read: " + e.getMessage());
            }
            try {
                Credentials parsedRes = res.getValue(Credentials.class);
                assertThat("JSON response was null", parsedRes, notNullValue());
                assertThat("JSON response incorrect", parsedRes.getUsername(), is("user"));
                assertThat("JSON response incorrect", parsedRes.getPassword(), is("password"));
            } catch (InvalidResponseException e) {
                fail("JSON response could not be parsed: " + e.getMessage());
            }

            /* Try to read accessible path with JSON value */
            try {
                res = connector.readSecret(SECRET_PATH + "/" + SECRET_KEY_JSON);
                assertThat("Known secret returned null value.", res.getValue(), notNullValue());
            } catch (VaultConnectorException e) {
                fail("Valid secret path could not be read: " + e.getMessage());
            }
            try {
                Credentials parsedRes = res.getValue(Credentials.class);
                assertThat("JSON response was null", parsedRes, notNullValue());
                assertThat("JSON response incorrect", parsedRes.getUsername(), is("user"));
                assertThat("JSON response incorrect", parsedRes.getPassword(), is("password"));
            } catch (InvalidResponseException e) {
                fail("JSON response could not be parsed: " + e.getMessage());
            }

            /* Try to read accessible complex secret */
            try {
                res = connector.readSecret(SECRET_PATH + "/" + SECRET_KEY_COMPLEX);
                assertThat("Known secret returned null value.", res.getData(), notNullValue());
                assertThat("Unexpected value size", res.getData().keySet(), hasSize(2));
                assertThat("Unexpected value", res.get("key1"), is("value1"));
                assertThat("Unexpected value", res.get("key2"), is("value2"));
            } catch (VaultConnectorException e) {
                fail("Valid secret path could not be read: " + e.getMessage());
            }
        }

        /**
         * Test listing secrets.
         */
        @Test
        @Order(20)
        @DisplayName("List secrets")
        public void listSecretsTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());
            /* Try to list secrets from valid path */
            try {
                List<String> secrets = connector.listSecrets(SECRET_PATH);
                assertThat("Invalid nmber of secrets.", secrets.size(), greaterThan(0));
                assertThat("Known secret key not found", secrets, hasItem(SECRET_KEY));
            } catch (VaultConnectorException e) {
                fail("Secrets could not be listed: " + e.getMessage());
            }
        }

        /**
         * Test writing secrets.
         */
        @Test
        @Order(30)
        @DisplayName("Write secrets")
        @SuppressWarnings("deprecation")
        public void writeSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            /* Try to write to null path */
            try {
                connector.writeSecret(null, "someValue");
                fail("Secret written to null path.");
            } catch (VaultConnectorException e) {
                assertThat(e, instanceOf(InvalidRequestException.class));
            }
            /* Try to write to invalid path */
            try {
                connector.writeSecret("", "someValue");
                fail("Secret written to invalid path.");
            } catch (VaultConnectorException e) {
                assertThat(e, instanceOf(InvalidRequestException.class));
            }
            /* Try to write to a path the user has no access for */
            try {
                connector.writeSecret("invalid/path", "someValue");
                fail("Secret written to inaccessible path.");
            } catch (VaultConnectorException e) {
                assertThat(e, instanceOf(PermissionDeniedException.class));
            }
            /* Perform a valid write/read roundtrip to valid path. Also check UTF8-encoding. */
            try {
                connector.writeSecret(SECRET_PATH + "/temp", "Abc123äöü,!");
            } catch (VaultConnectorException e) {
                fail("Secret written to inaccessible path.");
            }
            try {
                SecretResponse res = connector.readSecret(SECRET_PATH + "/temp");
                assertThat(res.getValue(), is("Abc123äöü,!"));
            } catch (VaultConnectorException e) {
                fail("Written secret could not be read.");
            }
        }

        /**
         * Test deletion of secrets.
         */
        @Test
        @Order(40)
        @DisplayName("Delete secrets")
        public void deleteSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            /* Write a test secret to vault */
            try {
                connector.writeSecret(SECRET_PATH + "/toDelete", "secret content");
            } catch (VaultConnectorException e) {
                fail("Secret written to inaccessible path.");
            }
            SecretResponse res = null;
            try {
                res = connector.readSecret(SECRET_PATH + "/toDelete");
            } catch (VaultConnectorException e) {
                fail("Written secret could not be read.");
            }
            assumeThat(res, is(notNullValue()));

            /* Delete secret */
            try {
                connector.deleteSecret(SECRET_PATH + "/toDelete");
            } catch (VaultConnectorException e) {
                fail("Revocation threw unexpected exception.");
            }

            /* Try to read again */
            try {
                connector.readSecret(SECRET_PATH + "/toDelete");
                fail("Successfully read deleted secret.");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
                assertThat(((InvalidResponseException) e).getStatusCode(), is(404));
            }
        }

        /**
         * Test revocation of secrets.
         */
        @Test
        @Order(50)
        @DisplayName("Revoke secrets")
        public void revokeTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            /* Write a test secret to vault */
            try {
                connector.writeSecret(SECRET_PATH + "/toRevoke", "secret content");
            } catch (VaultConnectorException e) {
                fail("Secret written to inaccessible path.");
            }
            SecretResponse res = null;
            try {
                res = connector.readSecret(SECRET_PATH + "/toRevoke");
            } catch (VaultConnectorException e) {
                fail("Written secret could not be read.");
            }
            assumeThat(res, is(notNullValue()));

            /* Revoke secret */
            try {
                connector.revoke(SECRET_PATH + "/toRevoke");
            } catch (VaultConnectorException e) {
                fail("Revocation threw unexpected exception.");
            }
        }
    }

    @Nested
    @DisplayName("KV v2 Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class KvV2Tests {
        // KV v2 secret with 2 versions.
        private static final String MOUNT_KV2 = "kv";
        private static final String SECRET2_KEY = "foo2";
        private static final String SECRET2_VALUE1 = "bar2";
        private static final String SECRET2_VALUE2 = "bar3";
        private static final String SECRET2_VALUE3 = "bar4";
        private static final String SECRET2_VALUE4 = "bar4";

        /**
         * Test reading of secrets from KV v2 store.
         */
        @Test
        @Order(10)
        @DisplayName("Read v2 secret")
        public void readSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to read accessible path with known value.
            SecretResponse res;
            try {
                res = connector.readSecretData(MOUNT_KV2, SECRET2_KEY);
                assertThat("Metadata not populated for KV v2 secret", res.getMetadata(), is(notNullValue()));
                assertThat("Unexpected secret version", res.getMetadata().getVersion(), is(2));
                assertThat("Known secret returned invalid value.", res.getValue(), is(SECRET2_VALUE2));
            } catch (VaultConnectorException e) {
                fail("Valid secret path could not be read: " + e.getMessage());
            }

            // Try to read different version of same secret.
            try {
                res = connector.readSecretVersion(MOUNT_KV2, SECRET2_KEY, 1);
                assertThat("Unexpected secret version", res.getMetadata().getVersion(), is(1));
                assertThat("Known secret returned invalid value.", res.getValue(), is(SECRET2_VALUE1));
            } catch (VaultConnectorException e) {
                fail("Valid secret version could not be read: " + e.getMessage());
            }
        }

        /**
         * Test writing of secrets to KV v2 store.
         */
        @Test
        @Order(20)
        @DisplayName("Write v2 secret")
        public void writeSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // First get the current version of the secret.
            int currentVersion = -1;
            try {
                MetadataResponse res = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                currentVersion = res.getMetadata().getCurrentVersion();
            } catch (VaultConnectorException e) {
                fail("Reading secret metadata failed: " + e.getMessage());
            }

            // Now write (update) the data and verify the version.
            try {
                Map<String, Object> data = new HashMap<>();
                data.put("value", SECRET2_VALUE3);
                SecretVersionResponse res = connector.writeSecretData(MOUNT_KV2, SECRET2_KEY, data);
                assertThat("Version not updated after writing secret", res.getMetadata().getVersion(), is(currentVersion + 1));
                currentVersion = res.getMetadata().getVersion();
            } catch (VaultConnectorException e) {
                fail("Writing secret to KV v2 store failed: " + e.getMessage());
            }

            // Verify the content.
            try {
                SecretResponse res = connector.readSecretData(MOUNT_KV2, SECRET2_KEY);
                assertThat("Data not updated correctly", res.getValue(), is(SECRET2_VALUE3));
            } catch (VaultConnectorException e) {
                fail("Reading secret from KV v2 store failed: " + e.getMessage());
            }

            // Now try with explicit CAS value (invalid).
            try {
                Map<String, Object> data = new HashMap<>();
                data.put("value", SECRET2_VALUE4);
                SecretVersionResponse res = connector.writeSecretData(MOUNT_KV2, SECRET2_KEY, data, currentVersion - 1);
                fail("Writing secret to KV v2 with invalid CAS value succeeded");
            } catch (VaultConnectorException e) {
                assertThat("Unexpected exception", e, is(instanceOf(InvalidResponseException.class)));
            }

            // And finally with a correct CAS value.
            try {
                Map<String, Object> data = new HashMap<>();
                data.put("value", SECRET2_VALUE4);
                SecretVersionResponse res = connector.writeSecretData(MOUNT_KV2, SECRET2_KEY, data, currentVersion);
            } catch (VaultConnectorException e) {
                fail("Writing secret to KV v2 with correct CAS value failed: " + e.getMessage());
            }
        }

        /**
         * Test reading of secret metadata from KV v2 store.
         */
        @Test
        @Order(30)
        @DisplayName("Read v2 metadata")
        public void readSecretMetadataTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Read current metadata first.
            Integer maxVersions = -1;
            try {
                MetadataResponse res = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                maxVersions = res.getMetadata().getMaxVersions();
                assumeThat("Unexpected maximum number of versions", res.getMetadata().getMaxVersions(), is(10));
            } catch (VaultConnectorException e) {
                fail("Reading secret metadata failed: " + e.getMessage());
            }

            // Now update the metadata.
            try {
                ++maxVersions;
                connector.updateSecretMetadata(MOUNT_KV2, SECRET2_KEY, maxVersions, true);
            } catch (VaultConnectorException e) {
                fail("Updating secret metadata failed: " + e.getMessage());
            }

            // And verify the result.
            try {
                MetadataResponse res = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                assertThat("Unexpected maximum number of versions", res.getMetadata().getMaxVersions(), is(maxVersions));
            } catch (VaultConnectorException e) {
                fail("Reading secret metadata failed: " + e.getMessage());
            }
        }

        /**
         * Test updating secret metadata in KV v2 store.
         */
        @Test
        @Order(40)
        @DisplayName("Update v2 metadata")
        public void updateSecretMetadataTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to read accessible path with known value.
            try {
                MetadataResponse res = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                assertThat("Metadata not populated for KV v2 secret", res.getMetadata(), is(notNullValue()));
                assertThat("Unexpected secret version", res.getMetadata().getCurrentVersion(), is(2));
                assertThat("Unexpected number of secret versions", res.getMetadata().getVersions().size(), is(2));
                assertThat("Creation date should be present", res.getMetadata().getCreatedTime(), is(notNullValue()));
                assertThat("Update date should be present", res.getMetadata().getUpdatedTime(), is(notNullValue()));
                assertThat("Unexpected maximum number of versions", res.getMetadata().getMaxVersions(), is(10));
            } catch (VaultConnectorException e) {
                fail("Valid secret path could not be read: " + e.getMessage());
            }
        }

        /**
         * Test deleting specific secret versions from KV v2 store.
         */
        @Test
        @Order(50)
        @DisplayName("Version handling")
        public void handleSecretVersionsTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to delete inexisting versions.
            MetadataResponse meta;
            try {
                connector.deleteSecretVersions(MOUNT_KV2, SECRET2_KEY, 5, 42);
                meta = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
            } catch (VaultConnectorException e) {
                fail("Revealed non-existence of secret versions");
            }

            // Now delete existing version and verify.
            try {
                connector.deleteSecretVersions(MOUNT_KV2, SECRET2_KEY, 1);
                meta = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                assertThat("Expected deletion time for secret 1", meta.getMetadata().getVersions().get(1).getDeletionTime(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("Deleting existing version failed");
            }

            // Undelete the just deleted version.
            try {
                connector.undeleteSecretVersions(MOUNT_KV2, SECRET2_KEY, 1);
                meta = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                assertThat("Expected deletion time for secret 1 to be reset", meta.getMetadata().getVersions().get(1).getDeletionTime(), is(nullValue()));
            } catch (VaultConnectorException e) {
                fail("Undeleting existing version failed");
            }

            // Now destroy it.
            try {
                connector.destroySecretVersions(MOUNT_KV2, SECRET2_KEY, 1);
                meta = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                assertThat("Expected secret 1 to be marked destroyed", meta.getMetadata().getVersions().get(1).isDestroyed(), is(true));
            } catch (VaultConnectorException e) {
                fail("Destroying existing version failed");
            }

            // Delete latest version.
            try {
                connector.deleteLatestSecretVersion(MOUNT_KV2, SECRET2_KEY);
                meta = connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                assertThat("Expected secret 2 to be deleted", meta.getMetadata().getVersions().get(2).getDeletionTime(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("Deleting latest version failed");
            }

            // Delete all versions.
            try {
                connector.deleteAllSecretVersions(MOUNT_KV2, SECRET2_KEY);
            } catch (VaultConnectorException e) {
                fail("Deleting latest version failed: " + e.getMessage());
            }
            try {
                connector.readSecretMetadata(MOUNT_KV2, SECRET2_KEY);
                fail("Reading metadata of deleted secret should not succeed");
            } catch (Exception e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
            }
        }
    }

    @Nested
    @DisplayName("App-ID Tests")
    class AppIdTests {
        private static final String APP_ID = "152AEA38-85FB-47A8-9CBD-612D645BFACA";
        private static final String USER_ID = "5ADF8218-D7FB-4089-9E38-287465DBF37E";

        /**
         * App-ID authentication roundtrip.
         */
        @Test
        @Order(10)
        @DisplayName("Authenticate with App-ID")
        @SuppressWarnings("deprecation")
        public void authAppIdTest() {
            /* Try unauthorized access first. */
            assumeFalse(connector.isAuthorized());

            try {
                connector.registerAppId("", "", "");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }
            try {
                connector.registerUserId("", "");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }
        }

        /**
         * App-ID authentication roundtrip.
         */
        @Test
        @Order(20)
        @DisplayName("Register App-ID")
        @SuppressWarnings("deprecation")
        public void registerAppIdTest() {
            /* Authorize. */
            authRoot();
            assumeTrue(connector.isAuthorized());

            /* Register App-ID */
            try {
                boolean res = connector.registerAppId(APP_ID, "user", "App Name");
                assertThat("Failed to register App-ID", res, is(true));
            } catch (VaultConnectorException e) {
                fail("Failed to register App-ID: " + e.getMessage());
            }

            /* Register User-ID */
            try {
                boolean res = connector.registerUserId(APP_ID, USER_ID);
                assertThat("Failed to register App-ID", res, is(true));
            } catch (VaultConnectorException e) {
                fail("Failed to register App-ID: " + e.getMessage());
            }

            connector.resetAuth();
            assumeFalse(connector.isAuthorized());

            /* Authenticate with created credentials */
            try {
                AuthResponse res = connector.authAppId(APP_ID, USER_ID);
                assertThat("Authorization flag not set after App-ID login.", connector.isAuthorized(), is(true));
            } catch (VaultConnectorException e) {
                fail("Failed to authenticate using App-ID: " + e.getMessage());
            }
        }
    }

    @Nested
    @DisplayName("AppRole Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class AppRoleTests {
        private static final String APPROLE_ROLE_NAME = "testrole1";                          // role with secret ID
        private static final String APPROLE_ROLE = "06eae026-7d4b-e4f8-0ec4-4107eb483975";
        private static final String APPROLE_SECRET = "20320293-c1c1-3b22-20f8-e5c960da0b5b";
        private static final String APPROLE_SECRET_ACCESSOR = "3b45a7c2-8d1c-abcf-c732-ecf6db16a8e1";
        private static final String APPROLE_ROLE2_NAME = "testrole2";                         // role with CIDR subnet
        private static final String APPROLE_ROLE2 = "40224890-1563-5193-be4b-0b4f9f573b7f";

        /**
         * App-ID authentication roundtrip.
         */
        @Test
        @Order(10)
        @DisplayName("Authenticate with AppRole")
        public void authAppRole() {
            assumeFalse(connector.isAuthorized());

            /* Authenticate with correct credentials */
            try {
                AuthResponse res = connector.authAppRole(APPROLE_ROLE, APPROLE_SECRET);
                assertThat("Authorization flag not set after AppRole login.", connector.isAuthorized(), is(true));
            } catch (VaultConnectorException e) {
                fail("Failed to authenticate using AppRole: " + e.getMessage());
            }

            /* Authenticate with valid secret ID against unknown role */
            final String invalidRole = "foo";
            try {
                connector.authAppRole(invalidRole, APPROLE_SECRET);
                fail("Successfully logged in with unknown role");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
                /* Assert that the exception does not reveal role ID or secret */
                assertThat(stackTrace(e), not(stringContainsInOrder(invalidRole)));
                assertThat(stackTrace(e), not(stringContainsInOrder(APPROLE_SECRET)));
            }

            /* Authenticate without wrong secret ID */
            final String invalidSecret = "foo";
            try {
                AuthResponse res = connector.authAppRole(APPROLE_ROLE, "foo");
                fail("Successfully logged in without secret ID");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
                /* Assert that the exception does not reveal role ID or secret */
                assertThat(stackTrace(e), not(stringContainsInOrder(APPROLE_ROLE)));
                assertThat(stackTrace(e), not(stringContainsInOrder(invalidSecret)));
            }

            /* Authenticate without secret ID */
            try {
                AuthResponse res = connector.authAppRole(APPROLE_ROLE);
                fail("Successfully logged in without secret ID");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
                /* Assert that the exception does not reveal role ID */
                assertThat(stackTrace(e), not(stringContainsInOrder(APPROLE_ROLE)));
            }

            /* Authenticate with secret ID on role with CIDR whitelist */
            try {
                AuthResponse res = connector.authAppRole(APPROLE_ROLE2, APPROLE_SECRET);
                assertThat("Authorization flag not set after AppRole login.", connector.isAuthorized(), is(true));
            } catch (VaultConnectorException e) {
                fail("Failed to log in without secret ID");
            }
        }

        /**
         * Test listing of AppRole roles and secrets.
         */
        @Test
        @Order(20)
        @DisplayName("List AppRoles")
        public void listAppRoleTest() {
            /* Try unauthorized access first. */
            assumeFalse(connector.isAuthorized());

            try {
                connector.listAppRoles();
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.listAppRoleSecrets("");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            /* Authorize. */
            authRoot();
            assumeTrue(connector.isAuthorized());

            /* Verify pre-existing rules */
            try {
                List<String> res = connector.listAppRoles();
                assertThat("Unexpected number of AppRoles", res, hasSize(2));
                assertThat("Pre-configured roles not listed", res, containsInAnyOrder(APPROLE_ROLE_NAME, APPROLE_ROLE2_NAME));
            } catch (VaultConnectorException e) {
                fail("Role listing failed.");
            }

            /* Check secret IDs */
            try {
                List<String> res = connector.listAppRoleSecrets(APPROLE_ROLE_NAME);
                assertThat("Unexpected number of AppRole secrets", res, hasSize(1));
                assertThat("Pre-configured AppRole secret not listed", res, contains(APPROLE_SECRET_ACCESSOR));
            } catch (VaultConnectorException e) {
                fail("AppRole secret listing failed.");
            }
        }


        /**
         * Test creation of a new AppRole.
         */
        @Test
        @Order(30)
        @DisplayName("Create AppRole")
        public void createAppRoleTest() {
            /* Try unauthorized access first. */
            assumeFalse(connector.isAuthorized());
            try {
                connector.createAppRole(new AppRole());
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.lookupAppRole("");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.deleteAppRole("");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.getAppRoleID("");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.setAppRoleID("", "");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.createAppRoleSecret("", "");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.lookupAppRoleSecret("", "");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            try {
                connector.destroyAppRoleSecret("", "");
                fail("Expected exception not thrown");
            } catch (Exception e) {
                assertThat("Unexpected exception class", e, is(instanceOf(AuthorizationRequiredException.class)));
            }

            /* Authorize. */
            authRoot();
            assumeTrue(connector.isAuthorized());

            String roleName = "TestRole";

            /* Create role model */
            AppRole role = AppRole.builder(roleName).build();

            /* Create role */
            try {
                boolean res = connector.createAppRole(role);
                assertThat("No result given.", res, is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("Role creation failed.");
            }

            /* Lookup role */
            try {
                AppRoleResponse res = connector.lookupAppRole(roleName);
                assertThat("Role lookup returned no role.", res.getRole(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("Role lookup failed.");
            }

            /* Lookup role ID */
            String roleID = "";
            try {
                roleID = connector.getAppRoleID(roleName);
                assertThat("Role ID lookup returned empty ID.", roleID, is(not(emptyString())));
            } catch (VaultConnectorException e) {
                fail("Role ID lookup failed.");
            }

            /* Set custom role ID */
            roleID = "custom-role-id";
            try {
                connector.setAppRoleID(roleName, roleID);
            } catch (VaultConnectorException e) {
                fail("Setting custom role ID failed.");
            }

            /* Verify role ID */
            try {
                String res = connector.getAppRoleID(roleName);
                assertThat("Role ID lookup returned wrong ID.", res, is(roleID));
            } catch (VaultConnectorException e) {
                fail("Role ID lookup failed.");
            }

            /* Create role by name */
            roleName = "RoleByName";
            try {
                connector.createAppRole(roleName);
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }
            try {
                AppRoleResponse res = connector.lookupAppRole(roleName);
                assertThat("Role lookuo returned not value", res.getRole(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }

            /* Create role by name with custom ID */
            roleName = "RoleByName";
            roleID = "RolyByNameID";
            try {
                connector.createAppRole(roleName, roleID);
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }
            try {
                AppRoleResponse res = connector.lookupAppRole(roleName);
                assertThat("Role lookuo returned not value", res.getRole(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }

            try {
                String res = connector.getAppRoleID(roleName);
                assertThat("Role lookuo returned wrong ID", res, is(roleID));
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }

            /* Create role by name with policies */
            try {
                connector.createAppRole(roleName, Collections.singletonList("testpolicy"));
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }
            try {
                AppRoleResponse res = connector.lookupAppRole(roleName);
                // Note: As of Vault 0.8.3 default policy is not added automatically, so this test should return 1, not 2.
                assertThat("Role lookuo returned wrong policy count (before Vault 0.8.3 is should be 2)", res.getRole().getPolicies(), hasSize(1));
                assertThat("Role lookuo returned wrong policies", res.getRole().getPolicies(), hasItem("testpolicy"));
            } catch (VaultConnectorException e) {
                fail("Creation of role by name failed.");
            }

            /* Delete role */
            try {
                connector.deleteAppRole(roleName);
            } catch (VaultConnectorException e) {
                fail("Deletion of role failed.");
            }
            try {
                connector.lookupAppRole(roleName);
                fail("Deleted role could be looked up.");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
            }
        }

        /**
         * Test creation of AppRole secrets.
         */
        @Test
        @Order(40)
        @DisplayName("Create AppRole secrets")
        public void createAppRoleSecretTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            /* Create default (random) secret for existing role */
            try {
                AppRoleSecretResponse res = connector.createAppRoleSecret(APPROLE_ROLE_NAME);
                assertThat("No secret returned", res.getSecret(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("AppRole secret creation failed.");
            }

            /* Create secret with custom ID */
            String secretID = "customSecretId";
            try {
                AppRoleSecretResponse res = connector.createAppRoleSecret(APPROLE_ROLE_NAME, secretID);
                assertThat("Unexpected secret ID returned", res.getSecret().getId(), is(secretID));
            } catch (VaultConnectorException e) {
                fail("AppRole secret creation failed.");
            }

            /* Lookup secret */
            try {
                AppRoleSecretResponse res = connector.lookupAppRoleSecret(APPROLE_ROLE_NAME, secretID);
                assertThat("No secret information returned", res.getSecret(), is(notNullValue()));
            } catch (VaultConnectorException e) {
                fail("AppRole secret lookup failed.");
            }

            /* Destroy secret */
            try {
                connector.destroyAppRoleSecret(APPROLE_ROLE_NAME, secretID);
            } catch (VaultConnectorException e) {
                fail("AppRole secret destruction failed.");
            }
            try {
                AppRoleSecretResponse res = connector.lookupAppRoleSecret(APPROLE_ROLE_NAME, secretID);
                fail("Destroyed AppRole secret successfully read.");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
            }
        }
    }

    @Nested
    @DisplayName("Token Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class TokenTests {
        /**
         * Test authentication using token.
         */
        @Test
        @Order(10)
        @DisplayName("Authenticate with token")
        public void authTokenTest() {
            TokenResponse res;
            final String invalidToken = "52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6";
            try {
                connector.authToken(invalidToken);
                fail("Logged in with invalid token");
            } catch (VaultConnectorException e) {
                /* Assert that the exception does not reveal the token */
                assertThat(stackTrace(e), not(stringContainsInOrder(invalidToken)));
            }

            try {
                res = connector.authToken(TOKEN_ROOT);
                assertNotNull(res, "Login failed with valid token");
                assertThat("Login failed with valid token", connector.isAuthorized(), is(true));
            } catch (VaultConnectorException ignored) {
                fail("Login failed with valid token");
            }
        }

        /**
         * Test revocation of secrets.
         */
        @Test
        @Order(20)
        @DisplayName("Create token")
        public void createTokenTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            /* Create token */
            Token token = Token.builder()
                    .withId("test-id")
                    .withDisplayName("test name")
                    .build();

            /* Create token */
            try {
                AuthResponse res = connector.createToken(token);
                assertThat("No result given.", res, is(notNullValue()));
                assertThat("Invalid token ID returned.", res.getAuth().getClientToken(), is("test-id"));
                assertThat("Invalid number of policies returned.", res.getAuth().getPolicies(), hasSize(1));
                assertThat("Root policy not inherited.", res.getAuth().getPolicies(), contains("root"));
                assertThat("Metadata unexpected.", res.getAuth().getMetadata(), is(nullValue()));
                assertThat("Root token should not be renewable", res.getAuth().isRenewable(), is(false));

                // Starting with Vault 1.0 a warning "cusotm ID uses weaker SHA1..." is given.
                if (VAULT_VERSION.startsWith("1.")) {
                    assertThat("Token creation did not return expected warning.", res.getWarnings(), hasSize(1));
                } else {
                    assertThat("Token creation returned warnings.", res.getWarnings(), is(nullValue()));
                }
            } catch (VaultConnectorException e) {
                fail("Token creation failed: " + e.getMessage());
            }

            /* Create token with attributes */
            token = Token.builder()
                    .withId("test-id2")
                    .withDisplayName("test name 2")
                    .withPolicies(Collections.singletonList("testpolicy"))
                    .withoutDefaultPolicy()
                    .withMeta("foo", "bar")
                    .build();
            try {
                AuthResponse res = connector.createToken(token);
                assertThat("Invalid token ID returned.", res.getAuth().getClientToken(), is("test-id2"));
                assertThat("Invalid number of policies returned.", res.getAuth().getPolicies(), hasSize(1));
                assertThat("Root policy not inherited.", res.getAuth().getPolicies(), contains("testpolicy"));
                assertThat("Metadata not given.", res.getAuth().getMetadata(), is(notNullValue()));
                assertThat("Metadata not correct.", res.getAuth().getMetadata().get("foo"), is("bar"));
                assertThat("Token should be renewable", res.getAuth().isRenewable(), is(true));
            } catch (VaultConnectorException e) {
                fail("Secret written to inaccessible path.");
            }

            /* Overwrite token should fail as of Vault 0.8.0 */
            token = Token.builder()
                    .withId("test-id2")
                    .withDisplayName("test name 3")
                    .withPolicies(Arrays.asList("pol1", "pol2"))
                    .withDefaultPolicy()
                    .withMeta("test", "success")
                    .withMeta("key", "value")
                    .withTtl(1234)
                    .build();
            try {
                connector.createToken(token);
                fail("Overwriting token should fail as of Vault 0.8.0");
            } catch (VaultConnectorException e) {
                assertThat(e, is(instanceOf(InvalidResponseException.class)));
                assertThat(((InvalidResponseException) e).getStatusCode(), is(400));
                /* Assert that the exception does not reveal token ID */
                assertThat(stackTrace(e), not(stringContainsInOrder(token.getId())));
            }
        }
    }

    @Nested
    @DisplayName("Misc Tests")
    class MiscTests {
        /**
         * Test listing of authentication backends
         */
        @Test
        @DisplayName("List auth methods")
        public void authMethodsTest() {
            /* Authenticate as valid user */
            try {
                connector.authToken(TOKEN_ROOT);
            } catch (VaultConnectorException ignored) {
            }
            assumeTrue(connector.isAuthorized());

            List<AuthBackend> supportedBackends = null;
            try {
                supportedBackends = connector.getAuthBackends();
            } catch (VaultConnectorException e) {
                fail("Could not list supported auth backends: " + e.getMessage());
            }
            assertThat(supportedBackends, hasSize(4));
            assertThat(supportedBackends, hasItems(AuthBackend.TOKEN, AuthBackend.USERPASS, AuthBackend.APPID, AuthBackend.APPROLE));
        }

        /**
         * Test authentication using username and password.
         */
        @Test
        @DisplayName("Authenticate with UserPass")
        public void authUserPassTest() {
            AuthResponse res = null;
            final String invalidUser = "foo";
            final String invalidPass = "bar";
            try {
                connector.authUserPass(invalidUser, invalidPass);
                fail("Logged in with invalid credentials");
            } catch (VaultConnectorException e) {
                /* Assert that the exception does not reveal credentials */
                assertThat(stackTrace(e), not(stringContainsInOrder(invalidUser)));
                assertThat(stackTrace(e), not(stringContainsInOrder(invalidPass)));
            }

            try {
                res = connector.authUserPass(USER_VALID, PASS_VALID);
            } catch (VaultConnectorException ignored) {
                fail("Login failed with valid credentials: Exception thrown");
            }
            assertNotNull(res.getAuth(), "Login failed with valid credentials: Response not available");
            assertThat("Login failed with valid credentials: Connector not authorized", connector.isAuthorized(), is(true));
        }

        /**
         * Test TLS connection with custom certificate chain.
         */
        @Test
        @Tag("tls")
        @DisplayName("TLS connection test")
        public void tlsConnectionTest() {
            TokenResponse res;
            try {
                connector.authToken("52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6");
                fail("Logged in with invalid token");
            } catch (VaultConnectorException ignored) {
            }

            try {
                res = connector.authToken(TOKEN_ROOT);
                assertNotNull(res, "Login failed with valid token");
                assertThat("Login failed with valid token", connector.isAuthorized(), is(true));
            } catch (VaultConnectorException ignored) {
                fail("Login failed with valid token");
            }
        }

        /**
         * Test sealing and unsealing Vault.
         */
        @Test
        @DisplayName("Seal test")
        public void sealTest() throws VaultConnectorException {
            SealResponse sealStatus = connector.sealStatus();
            assumeFalse(sealStatus.isSealed());

            /* Unauthorized sealing should fail */
            try {
                connector.seal();
                fail("Unauthorized sealing succeeded");
            } catch (VaultConnectorException e) {
                assertThat("Vault sealed, although sealing failed", sealStatus.isSealed(), is(false));
            }

            /* Root user should be able to seal */
            authRoot();
            assumeTrue(connector.isAuthorized());
            try {
                connector.seal();
                sealStatus = connector.sealStatus();
                assertThat("Vault not sealed", sealStatus.isSealed(), is(true));
                sealStatus = connector.unseal(KEY2);
                assertThat("Vault unsealed with only 1 key", sealStatus.isSealed(), is(true));
                sealStatus = connector.unseal(KEY3);
                assertThat("Vault not unsealed", sealStatus.isSealed(), is(false));
            } catch (VaultConnectorException e) {
                fail("Sealing failed");
            }
        }

        /**
         * Test health status
         */
        @Test
        @DisplayName("Health test")
        public void healthTest() {
            HealthResponse res = null;
            try {
                res = connector.getHealth();
            } catch (VaultConnectorException e) {
                fail("Retrieving health status failed: " + e.getMessage());
            }
            assertThat("Health response should be set", res, is(notNullValue()));
            assertThat("Unexpected version", res.getVersion(), is(VAULT_VERSION));
            assertThat("Unexpected init status", res.isInitialized(), is(true));
            assertThat("Unexpected seal status", res.isSealed(), is(false));
            assertThat("Unexpected standby status", res.isStandby(), is(false));

            // No seal vault and verify correct status.
            authRoot();
            try {
                connector.seal();
                assumeTrue(connector.sealStatus().isSealed());
                connector.resetAuth();  // SHould work unauthenticated
            } catch (VaultConnectorException e) {
                fail("Unexpected exception on sealing: " + e.getMessage());
            }
            try {
                res = connector.getHealth();
            } catch (VaultConnectorException e) {
                fail("Retrieving health status failed when sealed: " + e.getMessage());
            }
            assertThat("Unexpected seal status", res.isSealed(), is(true));
        }

        /**
         * Test closing the connector.
         */
        @Test
        @DisplayName("Connector close test")
        public void closeTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            try {
                connector.close();
                assertThat("Not unauthorized after close().", connector.isAuthorized(), is(false));

                /* Verify that (private) token has indeed been removed */
                Field tokenField = HTTPVaultConnector.class.getDeclaredField("token");
                tokenField.setAccessible(true);
                assertThat("Token not removed after close().", tokenField.get(connector), is(nullValue()));
            } catch (Exception e) {
                fail("Closing the connector failed: " + e.getMessage());
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
    private VaultConfiguration initializeVault(File dir, boolean tls) throws IllegalStateException, IOException {
        File dataDir = new File(dir, "data");
        copyDirectory(new File(getClass().getResource("/data_dir").getPath()), dataDir);

        /* Generate vault local unencrypted configuration */
        VaultConfiguration config = new VaultConfiguration()
                .withHost("localhost")
                .withPort(getFreePort())
                .withDataLocation(dataDir.toPath())
                .disableMlock();

        /* Enable TLS with custom certificate and key, if required */
        if (tls) {
            config.enableTLS()
                    .withCert(getClass().getResource("/tls/server.pem").getPath())
                    .withKey(getClass().getResource("/tls/server.key").getPath());
        }

        /* Write configuration file */
        BufferedWriter bw = null;
        File configFile;
        try {
            configFile = new File(dir, "vault.conf");
            bw = new BufferedWriter(new FileWriter(configFile));
            bw.write(config.toString());
        } catch (IOException e) {
            throw new IllegalStateException("Unable to generate config file.", e);
        } finally {
            try {
                if (bw != null)
                    bw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        /* Start vault process */
        try {
            vaultProcess = Runtime.getRuntime().exec("vault server -config " + configFile.toString());
        } catch (IOException e) {
            throw new IllegalStateException("Unable to start vault. Make sure vault binary is in your executable path.", e);
        }

        return config;
    }

    /**
     * Authenticate with root token.
     */
    private void authRoot() {
        /* Authenticate as valid user */
        try {
            connector.authToken(TOKEN_ROOT);
        } catch (VaultConnectorException ignored) {
        }
    }

    /**
     * Authenticate with user credentials.
     */
    private void authUser() {
        try {
            connector.authUserPass(USER_VALID, PASS_VALID);
        } catch (VaultConnectorException ignored) {
        }
    }

    /**
     * Find and return a free TCP port.
     *
     * @return port number
     */
    private static Integer getFreePort() {
        ServerSocket socket = null;
        try {
            socket = new ServerSocket(0);
            socket.setReuseAddress(true);
            int port = socket.getLocalPort();
            try {
                socket.close();
            } catch (IOException e) {
                // Ignore IOException on close()
            }
            return port;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        throw new IllegalStateException("Unable to find a free TCP port.");
    }

    /**
     * Retrieve StackTrace from throwable as string
     *
     * @param th the throwable
     * @return the stack trace
     */
    private static String stackTrace(final Throwable th) {
        StringWriter sw = new StringWriter();
        th.printStackTrace(new PrintWriter(sw, true));
        return sw.getBuffer().toString();
    }
}
