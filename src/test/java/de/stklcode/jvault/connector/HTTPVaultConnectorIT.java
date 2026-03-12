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

package de.stklcode.jvault.connector;

import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.*;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.test.Credentials;
import de.stklcode.jvault.connector.test.VaultConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonMap;
import static org.apache.commons.io.FileUtils.copyDirectory;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * JUnit test for HTTP Vault connector.
 * This test requires Vault binary in executable Path as it instantiates a real Vault server on given test data.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
class HTTPVaultConnectorIT {
    private static String VAULT_VERSION = "2.0.3";  // The vault version this test is supposed to run against.
    private static final String KEY1 = "+5n9tlpFnTNBAyutYQLT0o5J0AQ6Lt85u2KrEOan4gzb";
    private static final String KEY2 = "4SSSIsllqY+c//t1M9IhBwzVSeBWgh0E0UbjacUD9/5g";
    private static final String KEY3 = "O7AMGCi9Blt7gHHJdFjz1sHZHsUIOnvdFIV+AN2NwCxv";
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
    void setUp(TestInfo testInfo, @TempDir File tempDir) throws VaultConnectorException, IOException {
        // Determine, if TLS is required.
        boolean isTls = testInfo.getTags().contains("tls");

        // Initialize Vault.
        VaultConfiguration config = initializeVault(tempDir, isTls);

        // Initialize connector.
        HTTPVaultConnectorBuilder builder = HTTPVaultConnector.builder()
            .withHost(config.getHost())
            .withPort(config.getPort())
            .withTLS(isTls);
        if (isTls) {
            builder.withTrustedCA(Paths.get(getClass().getResource("/tls/ca.pem").getPath()));
        }
        connector = builder.build();

        // Unseal Vault and check result.
        SealResponse sealStatus = connector.sys().unseal(KEY1);
        assumeTrue(sealStatus != null, "Seal status could not be determined after startup");
        assumeTrue(sealStatus.sealed(), "Vault is not sealed after startup");
        sealStatus = connector.sys().unseal(KEY2);
        assumeTrue(sealStatus != null, "Seal status could not be determined");
        assumeFalse(sealStatus.sealed(), "Vault is not unsealed");
        assumeTrue(sealStatus.initialized(), "Vault is not initialized"); // Initialized flag of Vault 0.11.2 (#20).
    }

    @AfterEach
    void tearDown() {
        if (vaultProcess != null && vaultProcess.isAlive())
            vaultProcess.destroy();
    }

    @Nested
    @DisplayName("Read/Write Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class ReadWriteTests {
        private static final String SECRET_PATH = "secret/userstore";
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
        void readSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to read path user has no permission to read.
            final String invalidPath = "secret/invalid/path";

            VaultConnectorException e = assertThrows(
                PermissionDeniedException.class,
                () -> connector.read(invalidPath),
                "Invalid secret path should raise an exception"
            );

            // Assert that the exception does not reveal secret or credentials.
            assertFalse(stackTrace(e).contains(invalidPath));
            assertFalse(stackTrace(e).contains(USER_VALID));
            assertFalse(stackTrace(e).contains(PASS_VALID));
            assertFalse(Pattern.compile("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}").matcher(stackTrace(e)).find());

            // Try to read accessible path with known value.
            SecretResponse res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/" + SECRET_KEY),
                "Valid secret path could not be read"
            );
            assertEquals(SECRET_VALUE, res.get("value"), "Known secret returned invalid value");

            // Try to read accessible path with JSON value.
            res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/" + SECRET_KEY_JSON),
                "Valid secret path could not be read"
            );
            assertNotNull(res.get("value"), "Known secret returned null value");

            SecretResponse finalRes = res;
            Credentials parsedRes = assertDoesNotThrow(() -> finalRes.get("value", Credentials.class), "JSON response could not be parsed");
            assertNotNull(parsedRes, "JSON response was null");
            assertEquals("user", parsedRes.getUsername(), "JSON response incorrect");
            assertEquals("password", parsedRes.getPassword(), "JSON response incorrect");

            // Try to read accessible path with JSON value.
            res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/" + SECRET_KEY_JSON),
                "Valid secret path could not be read"
            );
            assertNotNull(res.get("value"), "Known secret returned null value");

            SecretResponse finalRes1 = res;
            parsedRes = assertDoesNotThrow(() -> finalRes1.get("value", Credentials.class), "JSON response could not be parsed");
            assertNotNull(parsedRes, "JSON response was null");
            assertEquals("user", parsedRes.getUsername(), "JSON response incorrect");
            assertEquals("password", parsedRes.getPassword(), "JSON response incorrect");

            // Try to read accessible complex secret.
            res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/" + SECRET_KEY_COMPLEX),
                "Valid secret path could not be read"
            );
            assertNotNull(res.data(), "Known secret returned null value");
            assertEquals(Map.of("key1", "value1", "key2", "value2"), res.data(), "Unexpected data");
        }

        /**
         * Test listing secrets.
         */
        @Test
        @Order(20)
        @DisplayName("List secrets")
        void listSecretsTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());
            // Try to list secrets from valid path.
            List<String> secrets = assertDoesNotThrow(
                () -> connector.list(SECRET_PATH),
                "Secrets could not be listed"
            );
            assertNotEquals(0, secrets.size(), "Invalid number of secrets");
            assertTrue(secrets.contains(SECRET_KEY), "Known secret key not found");
        }

        /**
         * Test writing secrets.
         */
        @Test
        @Order(30)
        @DisplayName("Write secrets")
        void writeSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to write to null path.
            assertThrows(
                InvalidRequestException.class,
                () -> connector.write(null, "someValue"),
                "Secret written to null path"
            );

            // Try to write to invalid path.
            assertThrows(
                InvalidRequestException.class,
                () -> connector.write("", "someValue"),
                "Secret written to invalid path"
            );

            // Try to write to a path the user has no access for.
            assertThrows(
                PermissionDeniedException.class,
                () -> connector.write("invalid/path", "someValue"),
                "Secret written to inaccessible path"
            );

            // Perform a valid write/read roundtrip to valid path. Also check UTF8-encoding.
            assertDoesNotThrow(
                () -> connector.write(SECRET_PATH + "/temp", "Abc123äöü,!"),
                "Failed to write secret to accessible path"
            );
            SecretResponse res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/temp"),
                "Written secret could not be read"
            );
            assertEquals("Abc123äöü,!", res.get("value"));
        }

        /**
         * Test deletion of secrets.
         */
        @Test
        @Order(40)
        @DisplayName("Delete secrets")
        void deleteSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Write a test secret to vault.
            assertDoesNotThrow(
                () -> connector.write(SECRET_PATH + "/toDelete", "secret content"),
                "Secret written to inaccessible path"
            );
            SecretResponse res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/toDelete"),
                "Written secret could not be read"
            );
            assumeTrue(res != null);

            // Delete secret.
            assertDoesNotThrow(
                () -> connector.delete(SECRET_PATH + "/toDelete"),
                "Revocation threw unexpected exception"
            );

            // Try to read again.
            InvalidResponseException e = assertThrows(
                InvalidResponseException.class,
                () -> connector.read(SECRET_PATH + "/toDelete"),
                "Successfully read deleted secret"
            );
            assertEquals(404, e.getStatusCode());
        }

        /**
         * Test revocation of secrets.
         */
        @Test
        @Order(50)
        @DisplayName("Revoke secrets")
        void revokeTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            // Write a test secret to vault.
            assertDoesNotThrow(
                () -> connector.write(SECRET_PATH + "/toRevoke", "secret content"),
                "Secret written to inaccessible path"
            );
            SecretResponse res = assertDoesNotThrow(
                () -> connector.read(SECRET_PATH + "/toRevoke"),
                "Written secret could not be read"
            );
            assumeTrue(res != null);

            // Revoke secret.
            assertDoesNotThrow(
                () -> connector.revoke(SECRET_PATH + "/toRevoke"),
                "Revocation threw unexpected exception"
            );
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
        void readSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to read accessible path with known value.
            SecretResponse res = assertDoesNotThrow(
                () -> connector.kv2().readData(MOUNT_KV2, SECRET2_KEY),
                "Valid secret path could not be read"
            );
            assertNotNull(res.metadata(), "Metadata not populated for KV v2 secret");
            assertEquals(2, res.metadata().version(), "Unexpected secret version");
            assertEquals(SECRET2_VALUE2, res.get("value"), "Known secret returned invalid value");

            // Try to read different version of same secret.
            res = assertDoesNotThrow(
                () -> connector.kv2().readVersion(MOUNT_KV2, SECRET2_KEY, 1),
                "Valid secret version could not be read"
            );
            assertEquals(1, res.metadata().version(), "Unexpected secret version");
            assertEquals(SECRET2_VALUE1, res.get("value"), "Known secret returned invalid value");
        }

        /**
         * Test writing of secrets to KV v2 store.
         */
        @Test
        @Order(20)
        @DisplayName("Write v2 secret")
        void writeSecretTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // First get the current version of the secret.
            MetadataResponse res = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading secret metadata failed"
            );
            int currentVersion = res.metadata().currentVersion();

            // Now write (update) the data and verify the version.
            Map<String, Object> data = new HashMap<>();
            data.put("value", SECRET2_VALUE3);
            SecretVersionResponse res2 = assertDoesNotThrow(
                () -> connector.kv2().writeData(MOUNT_KV2, SECRET2_KEY, data),
                "Writing secret to KV v2 store failed"
            );
            assertEquals(currentVersion + 1, res2.metadata().version(), "Version not updated after writing secret");
            int currentVersion2 = res2.metadata().version();

            // Verify the content.
            SecretResponse res3 = assertDoesNotThrow(
                () -> connector.kv2().readData(MOUNT_KV2, SECRET2_KEY),
                "Reading secret from KV v2 store failed"
            );
            assertEquals(SECRET2_VALUE3, res3.get("value"), "Data not updated correctly");

            // Now try with explicit CAS value (invalid).
            Map<String, Object> data4 = singletonMap("value", SECRET2_VALUE4);
            assertThrows(
                InvalidResponseException.class,
                () -> connector.kv2().writeData(MOUNT_KV2, SECRET2_KEY, data4, currentVersion2 - 1),
                "Writing secret to KV v2 with invalid CAS value succeeded"
            );

            // And finally with a correct CAS value.
            Map<String, Object> data5 = singletonMap("value", SECRET2_VALUE4);
            assertDoesNotThrow(() -> connector.kv2().writeData(MOUNT_KV2, SECRET2_KEY, data5, currentVersion2));
        }

        /**
         * Test reading of secret metadata from KV v2 store.
         */
        @Test
        @Order(30)
        @DisplayName("Read v2 metadata")
        void readSecretMetadataTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Read current metadata first.
            MetadataResponse res = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading secret metadata failed"
            );
            Integer maxVersions = res.metadata().maxVersions();
            assumeTrue(10 == res.metadata().maxVersions(), "Unexpected maximum number of versions");

            // Now update the metadata.
            assertDoesNotThrow(
                () -> connector.kv2().updateMetadata(MOUNT_KV2, SECRET2_KEY, maxVersions + 1, true),
                "Updating secret metadata failed"
            );

            // And verify the result.
            res = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading secret metadata failed"
            );
            assertEquals(maxVersions + 1, res.metadata().maxVersions(), "Unexpected maximum number of versions");
        }

        /**
         * Test updating secret metadata in KV v2 store.
         */
        @Test
        @Order(40)
        @DisplayName("Update v2 metadata")
        void updateSecretMetadataTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to read accessible path with known value.
            MetadataResponse res = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Valid secret path could not be read"
            );
            assertNotNull(res.metadata(), "Metadata not populated for KV v2 secret");
            assertEquals(2, res.metadata().currentVersion(), "Unexpected secret version");
            assertEquals(2, res.metadata().versions().size(), "Unexpected number of secret versions");
            assertNotNull(res.metadata().createdTime(), "Creation date should be present");
            assertNotNull(res.metadata().updatedTime(), "Update date should be present");
            assertEquals(10, res.metadata().maxVersions(), "Unexpected maximum number of versions");
        }

        /**
         * Test deleting specific secret versions from KV v2 store.
         */
        @Test
        @Order(50)
        @DisplayName("Version handling")
        void handleSecretVersionsTest() {
            authUser();
            assumeTrue(connector.isAuthorized());

            // Try to delete non-existing versions.
            assertDoesNotThrow(
                () -> connector.kv2().deleteVersions(MOUNT_KV2, SECRET2_KEY, 5, 42),
                "Revealed non-existence of secret versions"
            );
            assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Revealed non-existence of secret versions"
            );

            // Now delete existing version and verify.
            assertDoesNotThrow(
                () -> connector.kv2().deleteVersions(MOUNT_KV2, SECRET2_KEY, 1),
                "Deleting existing version failed"
            );
            MetadataResponse meta = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading deleted secret metadata failed"
            );
            assertNotNull(
                meta.metadata().versions().get(1).deletionTime(),
                "Expected deletion time for secret 1"
            );

            // Undelete the just deleted version.
            assertDoesNotThrow(
                () -> connector.kv2().undeleteVersions(MOUNT_KV2, SECRET2_KEY, 1),
                "Undeleting existing version failed"
            );
            meta = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading deleted secret metadata failed"
            );
            assertNull(
                meta.metadata().versions().get(1).deletionTime(),
                "Expected deletion time for secret 1 to be reset"
            );

            // Now destroy it.
            assertDoesNotThrow(
                () -> connector.kv2().destroyVersions(MOUNT_KV2, SECRET2_KEY, 1),
                "Destroying existing version failed"
            );
            meta = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading destroyed secret metadata failed"
            );
            assertTrue(
                meta.metadata().versions().get(1).destroyed(),
                "Expected secret 1 to be marked destroyed"
            );

            // Delete latest version.
            assertDoesNotThrow(
                () -> connector.kv2().deleteLatestVersion(MOUNT_KV2, SECRET2_KEY),
                "Deleting latest version failed"
            );
            meta = assertDoesNotThrow(
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading deleted secret metadata failed"
            );
            assertNotNull(
                meta.metadata().versions().get(2).deletionTime(),
                "Expected secret 2 to be deleted"
            );

            // Delete all versions.
            assertDoesNotThrow(
                () -> connector.kv2().deleteAllVersions(MOUNT_KV2, SECRET2_KEY),
                "Deleting latest version failed"
            );
            assertThrows(
                InvalidResponseException.class,
                () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
                "Reading metadata of deleted secret should not succeed"
            );
        }
    }

    @Nested
    @DisplayName("AppRole Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class AppRoleTests {
        private static final String APPROLE_ROLE_NAME = "testrole1";                          // Role with secret ID.
        private static final String APPROLE_ROLE = "06eae026-7d4b-e4f8-0ec4-4107eb483975";
        private static final String APPROLE_SECRET = "20320293-c1c1-3b22-20f8-e5c960da0b5b";
        private static final String APPROLE_SECRET_ACCESSOR = "3b45a7c2-8d1c-abcf-c732-ecf6db16a8e1";
        private static final String APPROLE_ROLE2_NAME = "testrole2";                         // Role with CIDR subnet.
        private static final String APPROLE_ROLE2 = "40224890-1563-5193-be4b-0b4f9f573b7f";

        /**
         * App-ID authentication roundtrip.
         */
        @Test
        @Order(10)
        @DisplayName("Authenticate with AppRole")
        void authAppRole() {
            assumeFalse(connector.isAuthorized());

            // Authenticate with correct credentials.
            assertDoesNotThrow(
                () -> connector.authAppRole(APPROLE_ROLE, APPROLE_SECRET),
                "Failed to authenticate using AppRole"
            );
            assertTrue(connector.isAuthorized(), "Authorization flag not set after AppRole login");

            // Authenticate with valid secret ID against unknown role.
            final String invalidRole = "foo";
            InvalidResponseException e = assertThrows(
                InvalidResponseException.class,
                () -> connector.authAppRole(invalidRole, APPROLE_SECRET),
                "Successfully logged in with unknown role"
            );
            // Assert that the exception does not reveal role ID or secret.
            assertFalse(stackTrace(e).contains(invalidRole));
            assertFalse(stackTrace(e).contains(APPROLE_SECRET));

            // Authenticate without wrong secret ID.
            final String invalidSecret = "foo";
            e = assertThrows(
                InvalidResponseException.class,
                () -> connector.authAppRole(APPROLE_ROLE, "foo"),
                "Successfully logged in without secret ID"
            );
            // Assert that the exception does not reveal role ID or secret.
            assertFalse(stackTrace(e).contains(APPROLE_ROLE));
            assertFalse(stackTrace(e).contains(invalidSecret));

            // Authenticate without secret ID.
            e = assertThrows(
                InvalidResponseException.class,
                () -> connector.authAppRole(APPROLE_ROLE),
                "Successfully logged in without secret ID"
            );
            // Assert that the exception does not reveal role ID.
            assertFalse(stackTrace(e).contains(APPROLE_ROLE));

            // Authenticate with secret ID on role with CIDR whitelist.
            assertDoesNotThrow(
                () -> connector.authAppRole(APPROLE_ROLE2, APPROLE_SECRET),
                "Failed to log in without secret ID"
            );
            assertTrue(connector.isAuthorized(), "Authorization flag not set after AppRole login");
        }

        /**
         * Test listing of AppRole roles and secrets.
         */
        @Test
        @Order(20)
        @DisplayName("List AppRoles")
        void listAppRoleTest() {
            // Try unauthorized access first.
            assumeFalse(connector.isAuthorized());

            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().listRoles());

            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().listSecrets(""));

            // Authorize.
            authRoot();
            assumeTrue(connector.isAuthorized());

            // Verify pre-existing rules.
            List<String> res = assertDoesNotThrow(() -> connector.appRole().listRoles(), "Role listing failed");
            assertEquals(2, res.size(), "Unexpected number of AppRoles");
            assertTrue(res.containsAll(List.of(APPROLE_ROLE_NAME, APPROLE_ROLE2_NAME)), "Pre-configured roles not listed");

            // Check secret IDs.
            res = assertDoesNotThrow(() -> connector.appRole().listSecrets(APPROLE_ROLE_NAME), "AppRole secret listing failed");
            assertEquals(List.of(APPROLE_SECRET_ACCESSOR), res, "Pre-configured AppRole secret not listed");
        }

        /**
         * Test creation of a new AppRole.
         */
        @Test
        @Order(30)
        @DisplayName("Create AppRole")
        void createAppRoleTest() {
            // Try unauthorized access first.
            assumeFalse(connector.isAuthorized());
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().create(AppRole.builder(null).build()));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().lookup(""));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().delete(""));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().getRoleID(""));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().setRoleID("", ""));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().createSecret("", ""));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().lookupSecret("", ""));
            assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().destroySecret("", ""));

            // Authorize.
            authRoot();
            assumeTrue(connector.isAuthorized());

            String roleName = "TestRole";

            // Create role model.
            AppRole role = AppRole.builder(roleName).build();

            // Create role.
            boolean createRes = assertDoesNotThrow(() -> connector.appRole().create(role), "Role creation failed");
            assertTrue(createRes, "Role creation failed");

            // Lookup role.
            AppRoleResponse res = assertDoesNotThrow(() -> connector.appRole().lookup(roleName), "Role lookup failed");
            assertNotNull(res.role(), "Role lookup returned no role");

            // Lookup role ID.
            String roleID = assertDoesNotThrow(() -> connector.appRole().getRoleID(roleName), "Role ID lookup failed");
            assertNotEquals("", roleID, "Role ID lookup returned empty ID");

            // Set custom role ID.
            String roleID2 = "custom-role-id";
            assertDoesNotThrow(() -> connector.appRole().setRoleID(roleName, roleID2), "Setting custom role ID failed");

            // Verify role ID.
            String res2 = assertDoesNotThrow(() -> connector.appRole().getRoleID(roleName), "Role ID lookup failed");
            assertEquals(roleID2, res2, "Role ID lookup returned wrong ID");

            // Update role model with custom flags.
            AppRole role2 = AppRole.builder(roleName)
                .withTokenPeriod(321)
                .build();

            // Create role.
            boolean res3 = assertDoesNotThrow(() -> connector.appRole().create(role2), "Role creation failed");
            assertTrue(res3, "No result given");

            // Lookup updated role.
            res = assertDoesNotThrow(() -> connector.appRole().lookup(roleName), "Role lookup failed");
            assertNotNull(res.role(), "Role lookup returned no role");
            assertEquals(321, res.role().tokenPeriod(), "Token period not set for role");

            // Create role by name.
            String roleName2 = "RoleByName";
            assertDoesNotThrow(() -> connector.appRole().create(roleName2), "Creation of role by name failed");
            res = assertDoesNotThrow(() -> connector.appRole().lookup(roleName2), "Creation of role by name failed");
            assertNotNull(res.role(), "Role lookuo returned not value");

            // Create role by name with custom ID.
            String roleName3 = "RoleByName";
            String roleID3 = "RolyByNameID";
            assertDoesNotThrow(() -> connector.appRole().create(roleName3, roleID3), "Creation of role by name failed");
            res = assertDoesNotThrow(() -> connector.appRole().lookup(roleName3), "Creation of role by name failed");
            assertNotNull(res.role(), "Role lookuo returned not value");

            res2 = assertDoesNotThrow(() -> connector.appRole().getRoleID(roleName3), "Creation of role by name failed");
            assertEquals(roleID3, res2, "Role lookuo returned wrong ID");

            // Create role by name with policies.
            assertDoesNotThrow(
                () -> connector.appRole().create(roleName3, Collections.singletonList("testpolicy")),
                "Creation of role by name failed"
            );
            res = assertDoesNotThrow(() -> connector.appRole().lookup(roleName3), "Creation of role by name failed");
            // Note: As of Vault 0.8.3 default policy is not added automatically, so this test should return 1, not 2.
            assertEquals(List.of("testpolicy"), res.role().tokenPolicies(), "Role lookup returned unexpected policies");

            // Delete role.
            assertDoesNotThrow(() -> connector.appRole().delete(roleName3), "Deletion of role failed");
            assertThrows(
                InvalidResponseException.class,
                () -> connector.appRole().lookup(roleName3),
                "Deleted role could be looked up"
            );
        }

        /**
         * Test creation of AppRole secrets.
         */
        @Test
        @Order(40)
        @DisplayName("Create AppRole secrets")
        void createAppRoleSecretTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            // Create default (random) secret for existing role.
            AppRoleSecretResponse res = assertDoesNotThrow(
                () -> connector.appRole().createSecret(APPROLE_ROLE_NAME),
                "AppRole secret creation failed"
            );
            assertNotNull(res.secret(), "No secret returned");

            // Create secret with custom ID.
            String secretID = "customSecretId";
            res = assertDoesNotThrow(
                () -> connector.appRole().createSecret(APPROLE_ROLE_NAME, secretID),
                "AppRole secret creation failed"
            );
            assertEquals(secretID, res.secret().id(), "Unexpected secret ID returned");

            // Lookup secret.
            res = assertDoesNotThrow(
                () -> connector.appRole().lookupSecret(APPROLE_ROLE_NAME, secretID),
                "AppRole secret lookup failed"
            );
            assertNotNull(res.secret(), "No secret information returned");

            // Destroy secret.
            assertDoesNotThrow(
                () -> connector.appRole().destroySecret(APPROLE_ROLE_NAME, secretID),
                "AppRole secret destruction failed"
            );
            assertThrows(
                InvalidResponseException.class,
                () -> connector.appRole().lookupSecret(APPROLE_ROLE_NAME, secretID),
                "Destroyed AppRole secret successfully read"
            );
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
        void authTokenTest() {
            final String invalidToken = "52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6";
            VaultConnectorException e = assertThrows(
                VaultConnectorException.class,
                () -> connector.authToken(invalidToken),
                "Logged in with invalid token"
            );
            // Assert that the exception does not reveal the token.
            assertFalse(stackTrace(e).contains(invalidToken));


            TokenResponse res = assertDoesNotThrow(
                () -> connector.authToken(TOKEN_ROOT),
                "Login failed with valid token"
            );
            assertNotNull(res, "Login failed with valid token");
            assertTrue(connector.isAuthorized(), "Login failed with valid token");
        }

        /**
         * Test token creation.
         */
        @Test
        @Order(20)
        @DisplayName("Create token")
        void createTokenTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            // Create token.
            Token token = Token.builder()
                .withId("test-id")
                .withType(Token.Type.SERVICE)
                .withDisplayName("test name")
                .build();

            // Create token.
            AuthResponse res = assertDoesNotThrow(() -> connector.token().create(token), "Token creation failed");
            assertNotNull(res, "No result given");
            assertEquals("test-id", res.auth().clientToken(), "Invalid token ID returned");
            assertEquals(List.of("root"), res.auth().policies(), "Expected inherited root policy");
            assertEquals(List.of("root"), res.auth().tokenPolicies(), "Expected inherited root policy for token");
            assertEquals(Token.Type.SERVICE.value(), res.auth().tokenType(), "Unexpected token type");
            assertNull(res.auth().metadata(), "Metadata unexpected");
            assertFalse(res.auth().renewable(), "Root token should not be renewable");
            assertFalse(res.auth().orphan(), "Root token should not be orphan");

            // Starting with Vault 1.0 a warning "custom ID uses weaker SHA1..." is given.
            // Starting with Vault 1.11 a second warning "Endpoint ignored unrecognized parameters" is given.
            assertFalse(res.warnings().isEmpty(), "Token creation did not return expected warning");

            // Create token with attributes.
            Token token2 = Token.builder()
                .withId("test-id2")
                .withDisplayName("test name 2")
                .withPolicies(Collections.singletonList("testpolicy"))
                .withoutDefaultPolicy()
                .withMeta("foo", "bar")
                .build();
            res = assertDoesNotThrow(() -> connector.token().create(token2), "Token creation failed");
            assertEquals("test-id2", res.auth().clientToken(), "Invalid token ID returned");
            assertEquals(List.of("testpolicy"), res.auth().policies(), "Invalid policies returned");
            assertNotNull(res.auth().metadata(), "Metadata not given");
            assertEquals("bar", res.auth().metadata().get("foo"), "Metadata not correct");
            assertTrue(res.auth().renewable(), "Token should be renewable");

            // Overwrite token should fail as of Vault 0.8.0.
            Token token3 = Token.builder()
                .withId("test-id2")
                .withDisplayName("test name 3")
                .withPolicies(Arrays.asList("pol1", "pol2"))
                .withDefaultPolicy()
                .withMeta("test", "success")
                .withMeta("key", "value")
                .withTtl(1234L)
                .build();
            InvalidResponseException e = assertThrows(
                InvalidResponseException.class,
                () -> connector.token().create(token3),
                "Overwriting token should fail as of Vault 0.8.0"
            );
            assertEquals(400, e.getStatusCode());
            // Assert that the exception does not reveal token ID.
            assertFalse(stackTrace(e).contains(token3.id()));

            // Create token with batch type.
            Token token4 = Token.builder()
                .withDisplayName("test name 3")
                .withPolicy("batchpolicy")
                .withoutDefaultPolicy()
                .withType(Token.Type.BATCH)
                .build();
            res = assertDoesNotThrow(() -> connector.token().create(token4), "Token creation failed");
            assertTrue(
                // Expecting batch token. "hvb." Prefix as of Vault 1.10, "b." before.
                res.auth().clientToken().startsWith("b.") || res.auth().clientToken().startsWith("hvb."),
                "Unexpected token prefix"
            );
            assertEquals(1, res.auth().policies().size(), "Invalid number of policies returned");
            assertTrue(res.auth().policies().contains("batchpolicy"), "Custom policy policy not set");
            assertFalse(res.auth().renewable(), "Token should not be renewable");
            assertFalse(res.auth().orphan(), "Token should not be orphan");
            assertEquals(Token.Type.BATCH.value(), res.auth().tokenType(), "Specified token Type not set");
        }

        /**
         * Test token lookup.
         */
        @Test
        @Order(30)
        @DisplayName("Lookup token")
        void lookupTokenTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            // Create token with attributes.
            Token token = Token.builder()
                .withId("my-token")
                .withType(Token.Type.SERVICE)
                .build();
            assertDoesNotThrow(() -> connector.token().create(token), "Token creation failed");

            authRoot();
            assumeTrue(connector.isAuthorized());

            TokenResponse res = assertDoesNotThrow(() -> connector.token().lookup("my-token"), "Token creation failed");
            assertEquals(token.id(), res.data().id(), "Unexpected token ID");
            assertEquals(1, res.data().policies().size(), "Unexpected number of policies");
            assertTrue(res.data().policies().contains("root"), "Unexpected policy");
            assertEquals(token.type(), res.data().type(), "Unexpected token type");
            assertNotNull(res.data().issueTime(), "Issue time expected to be filled");
        }

        /**
         * Test token role handling.
         */
        @Test
        @Order(40)
        @DisplayName("Token roles")
        void tokenRolesTest() {
            authRoot();
            assumeTrue(connector.isAuthorized());

            // Create token role.
            final String roleName = "test-role";
            final TokenRole role = TokenRole.builder().build();

            boolean creationRes = assertDoesNotThrow(
                () -> connector.token().createOrUpdateRole(roleName, role),
                "Token role creation failed"
            );
            assertTrue(creationRes, "Token role creation failed");

            // Read the role.
            TokenRoleResponse res = assertDoesNotThrow(
                () -> connector.token().readRole(roleName),
                "Reading token role failed"
            );
            assertNotNull(res, "Token role response must not be null");
            assertNotNull(res.data(), "Token role must not be null");
            assertEquals(roleName, res.data().name(), "Token role name not as expected");
            assertTrue(res.data().renewable(), "Token role expected to be renewable by default");
            assertFalse(res.data().orphan(), "Token role not expected to be orphan by default");
            assertEquals(Token.Type.DEFAULT_SERVICE.value(), res.data().tokenType(), "Unexpected default token type");

            // Update the role, i.e. change some attributes.
            final TokenRole role2 = TokenRole.builder()
                .forName(roleName)
                .withPathSuffix("suffix")
                .orphan(true)
                .renewable(false)
                .withTokenNumUses(42)
                .build();

            creationRes = assertDoesNotThrow(
                () -> connector.token().createOrUpdateRole(role2),
                "Token role update failed"
            );
            assertTrue(creationRes, "Token role update failed");

            res = assertDoesNotThrow(() -> connector.token().readRole(roleName), "Reading token role failed");
            assertNotNull(res, "Token role response must not be null");
            assertNotNull(res.data(), "Token role must not be null");
            assertEquals(roleName, res.data().name(), "Token role name not as expected");
            assertFalse(res.data().renewable(), "Token role not expected to be renewable  after update");
            assertTrue(res.data().orphan(), "Token role expected to be orphan  after update");
            assertEquals(42, res.data().tokenNumUses(), "Unexpected number of token uses after update");

            // List roles.
            List<String> listRes = assertDoesNotThrow(() -> connector.token().listRoles(), "Listing token roles failed");
            assertNotNull(listRes, "Token role list must not be null");
            assertEquals(List.of(roleName), listRes, "Unexpected token role list");

            // Delete the role.
            creationRes = assertDoesNotThrow(() -> connector.token().deleteRole(roleName), "Token role deletion failed");
            assertTrue(creationRes, "Token role deletion failed");
            assertThrows(InvalidResponseException.class, () -> connector.token().readRole(roleName), "Reading nonexistent token role should fail");
            assertThrows(InvalidResponseException.class, () -> connector.token().listRoles(), "Listing nonexistent token roles should fail");
        }
    }

    @Nested
    @DisplayName("Transit Tests")
    class TransitTests {

        @Test
        @DisplayName("Transit encryption")
        void transitEncryptTest() {
            assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
            assumeTrue(connector.isAuthorized());

            TransitResponse transitResponse = assertDoesNotThrow(
                () -> connector.transit().encrypt("my-key", "dGVzdCBtZQ=="),
                "Failed to encrypt via transit"
            );
            assertNotNull(transitResponse.ciphertext());
            assertTrue(transitResponse.ciphertext().startsWith("vault:v1:"));

            transitResponse = assertDoesNotThrow(
                () -> connector.transit().encrypt("my-key", "test me".getBytes(UTF_8)),
                "Failed to encrypt binary data via transit"
            );
            assertNotNull(transitResponse.ciphertext());
            assertTrue(transitResponse.ciphertext().startsWith("vault:v1:"));

        }

        @Test
        @DisplayName("Transit decryption")
        void transitDecryptTest() {
            assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
            assumeTrue(connector.isAuthorized());

            TransitResponse transitResponse = assertDoesNotThrow(
                () -> connector.transit().decrypt("my-key", "vault:v1:1mhLVkBAR2nrFtIkJF/qg57DWfRj0FWgR6tvkGO8XOnL6sw="),
                "Failed to decrypt via transit"
            );

            assertEquals("dGVzdCBtZQ==", transitResponse.plaintext());
        }

        @Test
        @DisplayName("Transit hash")
        void transitHashText() {
            assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
            assumeTrue(connector.isAuthorized());

            TransitResponse transitResponse = assertDoesNotThrow(
                () -> connector.transit().hash("sha2-512", "dGVzdCBtZQ=="),
                "Failed to hash via transit"
            );

            assertEquals("7677af0ee4effaa9f35e9b1e82d182f79516ab8321786baa23002de7c06851059492dd37d5fc3791f17d81d4b58198d24a6fd8bbd62c42c1c30b371da500f193", transitResponse.sum());

            TransitResponse transitResponseBase64 = assertDoesNotThrow(
                () -> connector.transit().hash("sha2-256", "dGVzdCBtZQ==", "base64"),
                "Failed to hash via transit with base64 output"
            );

            assertEquals("5DfYkW7cvGLkfy36cXhqmZcygEy9HpnFNB4WWXKOl1M=", transitResponseBase64.sum());

            transitResponseBase64 = assertDoesNotThrow(
                () -> connector.transit().hash("sha2-256", "test me".getBytes(UTF_8), "base64"),
                "Failed to hash binary data via transit"
            );

            assertEquals("5DfYkW7cvGLkfy36cXhqmZcygEy9HpnFNB4WWXKOl1M=", transitResponseBase64.sum());
        }
    }

    @Nested
    @DisplayName("PKI Tests")
    class PkiTests {

        private static final String PKI_CA_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDLTCCAhWgAwIBAgIUQJcpa6gCLJWt+TowyNwVrdrjKlgwDQYJKoZIhvcNAQEL
            BQAwHjEcMBoGA1UEAxMTSlZhdWx0IFRlc3QgUm9vdCBDQTAeFw0yNjA3MTQxODIw
            MzlaFw0yNjA4MTUxODIxMDlaMB4xHDAaBgNVBAMTE0pWYXVsdCBUZXN0IFJvb3Qg
            Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDI0guomBRZlG9pJOBO
            y6lRqV7W616f6OS4mWryfICmE7C9emRahsjmlQSQGWO2mct3pwRyLFgSWpusiIkh
            jssnHM1qyaWeFv1EcjUByQM8xf8KFKqxxw5mX7jH0P0qfGOljvBAlpRa0HzPEYDT
            fhghYDo86a8JxW33VLha10MZJ+DU5r8SpbvzRfc4xdVF9PDDkxzq1hNMrVw2T/9l
            m3ycRWQ/T/uUT5Amx94yUPSQXZydcUjmA51hfdkmC5agSPSL1A1TBpAuTcv77M0I
            8wIejUbMCJOl8fFNAalySMg/1a2ZzFuRw7iXNuXcfNIH22z73hLnYfZ+hbElEa/2
            xUkzAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0G
            A1UdDgQWBBT5z9dFfwewhrtgEpHj4q7t+1fFcjAfBgNVHSMEGDAWgBT5z9dFfwew
            hrtgEpHj4q7t+1fFcjANBgkqhkiG9w0BAQsFAAOCAQEAnXecUvthG+PqJ2czn6Ag
            6vqhDtRcEc2DJv6VQWMEUt9R8QzWEQ7+XodyGlFtDx20O9Nhrhp3tKlQP6wqFsbs
            k8rkVGJ7fPVa/6aKjkSZ8BVWDEBfkkNE9pdtDlN7G2NFktG1ODco6i3pacEQtSLm
            6j7zmxJVxb3HGNgdZKdhHfGf0ABA9ErsiKf2Qwj0NPxa6Xhl+TsZKi8X+gwanYUs
            sx7kgm9uh9kurhKlaSrj8uV18RwyorsKqYxnFMUTRJ9QkNEhFFr1uc32W8Kj1mDo
            5e2D7/dUGCYLI95vqkyzynt0TWQEc43cZj0/LWlSRA+2wmDBDUqL1OwQfX1TDv2N
            TQ==
            -----END CERTIFICATE-----""";

        @BeforeEach
        void authorize() {
            assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
            assumeTrue(connector.isAuthorized());
        }

        @Test
        @DisplayName("Generate certificate and key")
        void generateCertificateAndKeyTest() {
            PkiResponse pkiResponse = assertDoesNotThrow(
                () -> connector.pki().generateCertificateAndKey(
                    "example-com",
                    PkiRequest.builder()
                        .withCommonName("test.example.com")
                        .withAltNames("test2.example.com")
                        .withIpSans("192.0.2.1")
                        .withKeyFormat(PkiRequest.KeyFormat.PKCS8)
                        .build()
                ),
                "Failed to issue certificate"
            );

            assertEquals("rsa", pkiResponse.data().privateKeyType(), "unexpected private key type");
            assertTrue(pkiResponse.data().expiration() > System.currentTimeMillis() / 1000L, "expiration timestamp should be in future");

            assertEquals(PKI_CA_PEM, pkiResponse.data().issuingCa(), "unexpected issuing CA certificate");
            if (compareVersions(VAULT_VERSION, "1.11.0") >= 0) {
                assertEquals(List.of(PKI_CA_PEM), pkiResponse.data().caChain(), "unexpected CA chain");
            }

            PublicKey caCert = parseCertificate(PKI_CA_PEM).getPublicKey();
            X509Certificate cert = parseCertificate(pkiResponse.data().certificate());
            assertNotNull(cert, "failed o parse certificate");
            assertNotNull(parsePrivateKey(pkiResponse.data().privateKey()), "failed o parse private key");
            assertDoesNotThrow(() -> cert.verify(caCert), "certificate was not signed by the issuing CA");

            assertHasSAN(cert, 2, "test.example.com");
            assertHasSAN(cert, 2, "test2.example.com");
            assertHasSAN(cert, 7, "192.0.2.1");
        }

        @Test
        @DisplayName("Revoke certificates")
        void revokeCertificateAndKeyTest() {
            // First, generate two certificates
            PkiResponse pkiResponse1 = assertDoesNotThrow(
                () -> connector.pki().generateCertificateAndKey("example-com",
                    PkiRequest.builder().withCommonName("a.example.com").build()),
                "Failed to issue certificate 1"
            );
            PkiResponse pkiResponse2 = assertDoesNotThrow(
                () -> connector.pki().generateCertificateAndKey("example-com",
                    PkiRequest.builder().withCommonName("b.example.com").build()),
                "Failed to issue certificate 2"
            );

            // Revoke first by serial
            PkiRevocationResponse res1 = assertDoesNotThrow(
                () -> connector.pki().revokeBySerial(pkiResponse1.data().serialNumber()),
                "Failed to revoke certificate 1 by serial"
            );
            assertNotNull(res1.data().revocationTime(), "missing revocation time in response");
            assertNotNull(res1.data().revocationTimeRFC3339(), "missing revocation time (RFC 3339) in response");
            if (compareVersions(VAULT_VERSION, "1.14.0") >= 0) {
                assertEquals("revoked", res1.data().state(), "unexpected state in response");
            }

            if (compareVersions(VAULT_VERSION, "1.12.0") >= 0) {
                // Revoke second by certificate
                PkiRevocationResponse res2 = assertDoesNotThrow(
                    () -> connector.pki().revokeCertificate(pkiResponse2.data().certificate()),
                    "Failed to revoke certificate 2 by PEM"
                );
                assertNotNull(res2.data().revocationTime(), "missing revocation time in response");
                assertNotNull(res2.data().revocationTimeRFC3339(), "missing revocation time (RFC 3339) in response");

                if (compareVersions(VAULT_VERSION, "1.14.0") >= 0) {
                    assertEquals("revoked", res2.data().state(), "unexpected state in response");
                }
            }

            InvalidResponseException ex = assertThrows(InvalidResponseException.class,
                () -> connector.pki().revokeBySerial("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"),
                "Expected exception on revoking non-existent certificate");
            assertEquals(400, ex.getStatusCode(), "unexpected status code in response");
            assertTrue(ex.getResponse().startsWith("certificate with serial 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 not found"),
                "unexpected error response message");
        }

        @Test
        @DisplayName("Read CA/issuer certificate")
        void readCaCertificateTest() {
            PkiCaResponse pkiResponse = assertDoesNotThrow(() -> connector.pki().readCaCert(),
                "Failed to read CA certificate");

            assertEquals(PKI_CA_PEM, pkiResponse.data().certificate(), "unexpected CA certificate");
            assertEquals(0, pkiResponse.data().revocationTime(), "unexpected revocation time");
            assertNull(pkiResponse.data().issuerId(), "unexpected issuer ID");
            assertNull(pkiResponse.data().issuerName(), "unexpected issuer name");

            if (pkiResponse.data().authorityKeyId() != null) {
                // Available in Vault 1.21.1+, but not in OpenBao (checked with 2.6.0)
                assertEquals("f9:cf:d7:45:7f:07:b0:86:bb:60:12:91:e3:e2:ae:ed:fb:57:c5:72",
                    pkiResponse.data().authorityKeyId(),
                    "unexpected authority key ID");
            }

            if (compareVersions(VAULT_VERSION, "1.11.0") >= 0) {
                assertEquals("", pkiResponse.data().revocationTimeRFC3339(), "unexpected revocation time (RFC 3339)");

                // Request a specific issuer
                pkiResponse = assertDoesNotThrow(() -> connector.pki().readIssuerCert("default"),
                    "Failed to read issuer certificate");

                assertEquals(PKI_CA_PEM + "\n", pkiResponse.data().certificate(), "unexpected CA certificate");
                assertEquals(List.of(PKI_CA_PEM + "\n"), pkiResponse.data().caChain(), "unexpected CA chain");
                assertNull(pkiResponse.data().revocationTime(), "unexpected revocation time");
                assertNull(pkiResponse.data().revocationTimeRFC3339(), "unexpected revocation time (RFC 3339)");
                // Issuers are not initialized in Vaul 1.3.0 test data, so dynamically assigned during upgrade
                assertNotNull(pkiResponse.data().issuerId(), "unexpected issuer ID");
                assertNotNull(pkiResponse.data().issuerName(), "unexpected issuer name");
            }
        }

        private static X509Certificate parseCertificate(String pem) {
            try {
                return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(UTF_8)));
            } catch (CertificateException e) {
                fail("Failed to parse certificate", e);
                return null;
            }
        }

        private static PrivateKey parsePrivateKey(String pem) {
            try {
                return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(
                        Base64.getDecoder().decode(
                            pem
                                .replace("-----BEGIN PRIVATE KEY-----", "")
                                .replaceAll(System.lineSeparator(), "")
                                .replace("-----END PRIVATE KEY-----", "")
                                .replaceAll("\\s", ""))
                    ));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                fail("Failed to parse private key", e);
                return null;
            }
        }

        private static void assertHasSAN(X509Certificate cert, Integer type, String san) {
            var rawSans = assertDoesNotThrow(cert::getSubjectAlternativeNames, "unable to extract SANs from certificate");
            assertNotNull(rawSans, "missing SANs in certificate");
            for (var item : rawSans) {
                if (item.size() == 2 && type.equals(item.get(0)) && san.equals(item.get(1))) {
                    return;
                }
            }

            fail("certificate does not contain SAN of type " + type + " and value " + san);
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
        void authMethodsTest() {
            // Authenticate as valid user.
            assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
            assumeTrue(connector.isAuthorized());

            List<AuthBackend> supportedBackends = assertDoesNotThrow(
                () -> connector.sys().getAuthBackends(),
                "Could not list supported auth backends"
            );

            assertEquals(3, supportedBackends.size());
            assertTrue(supportedBackends.containsAll(List.of(AuthBackend.TOKEN, AuthBackend.USERPASS, AuthBackend.APPROLE)));
        }

        /**
         * Test authentication using username and password.
         */
        @Test
        @DisplayName("Authenticate with UserPass")
        void authUserPassTest() {
            final String invalidUser = "foo";
            final String invalidPass = "bar";
            VaultConnectorException e = assertThrows(
                VaultConnectorException.class,
                () -> connector.authUserPass(invalidUser, invalidPass),
                "Logged in with invalid credentials"
            );
            // Assert that the exception does not reveal credentials.
            assertFalse(stackTrace(e).contains(invalidUser));
            assertFalse(stackTrace(e).contains(invalidPass));

            AuthResponse res = assertDoesNotThrow(
                () -> connector.authUserPass(USER_VALID, PASS_VALID),
                "Login failed with valid credentials: Exception thrown"
            );
            assertNotNull(res.auth(), "Login failed with valid credentials: Response not available");
            assertTrue(connector.isAuthorized(), "Login failed with valid credentials: Connector not authorized");
        }

        /**
         * Test TLS connection with custom certificate chain.
         */
        @Test
        @Tag("tls")
        @DisplayName("TLS connection test")
        void tlsConnectionTest() {
            assertThrows(
                VaultConnectorException.class,
                () -> connector.authToken("52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6"),
                "Logged in with invalid token"
            );

            TokenResponse res = assertDoesNotThrow(
                () -> connector.authToken(TOKEN_ROOT),
                "Login failed with valid token"
            );
            assertNotNull(res, "Login failed with valid token");
            assertTrue(connector.isAuthorized(), "Login failed with valid token");
        }

        /**
         * Test sealing and unsealing Vault.
         */
        @Test
        @DisplayName("Seal test")
        void sealTest() throws VaultConnectorException {
            SealResponse sealStatus = connector.sys().sealStatus();
            assumeFalse(sealStatus.sealed());

            // Unauthorized sealing should fail.
            assertThrows(VaultConnectorException.class, () -> connector.sys().seal(), "Unauthorized sealing succeeded");
            assertFalse(sealStatus.sealed(), "Vault sealed, although sealing failed");

            // Root user should be able to seal.
            authRoot();
            assumeTrue(connector.isAuthorized());
            assertDoesNotThrow(() -> connector.sys().seal(), "Sealing failed");
            sealStatus = connector.sys().sealStatus();
            assertTrue(sealStatus.sealed(), "Vault not sealed");
            sealStatus = connector.sys().unseal(KEY2);
            assertTrue(sealStatus.sealed(), "Vault unsealed with only 1 key");
            sealStatus = connector.sys().unseal(KEY3);
            assertFalse(sealStatus.sealed(), "Vault not unsealed");
        }

        /**
         * Test health status
         */
        @Test
        @DisplayName("Health test")
        void healthTest() {
            HealthResponse res = assertDoesNotThrow(() -> connector.sys().getHealth(), "Retrieving health status failed");
            assertNotNull(res, "Health response should be set");
            assertEquals(VAULT_VERSION, res.version(), "Unexpected version");
            assertTrue(res.initialized(), "Unexpected init status");
            assertFalse(res.sealed(), "Unexpected seal status");
            assertFalse(res.standby(), "Unexpected standby status");

            // No seal vault and verify correct status.
            authRoot();
            assertDoesNotThrow(() -> connector.sys().seal(), "Unexpected exception on sealing");
            SealResponse sealStatus = assertDoesNotThrow(() -> connector.sys().sealStatus());
            assumeTrue(sealStatus.sealed());
            connector.resetAuth();  // Should work unauthenticated
            res = assertDoesNotThrow(() -> connector.sys().getHealth(), "Retrieving health status failed when sealed");
            assertTrue(res.sealed(), "Unexpected seal status");
        }

        /**
         * Test closing the connector.
         */
        @Test
        @DisplayName("Connector close test")
        void closeTest() throws NoSuchFieldException, IllegalAccessException {
            authUser();
            assumeTrue(connector.isAuthorized());

            assertDoesNotThrow(connector::close, "Closing the connector failed");
            assertFalse(connector.isAuthorized(), "Not unauthorized after close()");

            // Verify that (private) token has indeed been removed.
            Field tokenField = HTTPVaultConnector.class.getDeclaredField("token");
            tokenField.setAccessible(true);
            assertNull(tokenField.get(connector), "Token not removed after close()");
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

        // Generate vault local unencrypted configuration.
        VaultConfiguration config = new VaultConfiguration()
            .withHost("localhost")
            .withPort(getFreePort())
            .withDataLocation(dataDir.toPath())
            .disableMlock();

        // Enable TLS with custom certificate and key, if required.
        if (tls) {
            config.enableTLS()
                .withCert(getClass().getResource("/tls/server.pem").getPath())
                .withKey(getClass().getResource("/tls/server.key").getPath());
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
    private void authRoot() {
        // Authenticate as valid user.
        assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
    }

    /**
     * Authenticate with user credentials.
     */
    private void authUser() {
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
    private static String stackTrace(final Throwable th) {
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
    private static int compareVersions(String version1, String version2) {
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
}
