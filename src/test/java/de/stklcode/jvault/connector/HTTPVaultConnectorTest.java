/*
 * Copyright 2016-2018 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.factory.HTTPVaultConnectorFactory;
import de.stklcode.jvault.connector.factory.VaultConnectorFactory;
import de.stklcode.jvault.connector.model.*;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.test.Credentials;
import de.stklcode.jvault.connector.test.VaultConfiguration;
import org.junit.Rule;
import org.junit.jupiter.api.*;
import org.junit.jupiter.migrationsupport.rules.EnableRuleMigrationSupport;
import org.junit.rules.TemporaryFolder;

import java.io.*;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
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
@EnableRuleMigrationSupport
public class HTTPVaultConnectorTest {
    private static final String VAULT_VERISON = "0.10.4";  // the vault version this test is supposed to run against
    private static final String KEY = "81011a8061e5c028bd0d9503eeba40bd9054b9af0408d080cb24f57405c27a61";
    private static final String TOKEN_ROOT = "d1bd50e2-587b-6e68-d80b-a9a507625cb7";
    private static final String USER_VALID = "validUser";
    private static final String PASS_VALID = "validPass";
    private static final String APP_ID = "152AEA38-85FB-47A8-9CBD-612D645BFACA";
    private static final String USER_ID = "5ADF8218-D7FB-4089-9E38-287465DBF37E";
    private static final String APPROLE_ROLE_NAME = "testrole1";                          // role with secret ID
    private static final String APPROLE_ROLE = "627b6400-90c3-a239-49a9-af65a448ca10";
    private static final String APPROLE_SECRET = "5e8b0e99-d906-27f5-f043-ccb9bb53b5e8";
    private static final String APPROLE_SECRET_ACCESSOR = "071e2e9d-742a-fc3c-3fd3-1f4004b0420a";
    private static final String APPROLE_ROLE2_NAME = "testrole2";                         // role with CIDR subnet
    private static final String APPROLE_ROLE2 = "35b7bf43-9644-588a-e68f-2e8313bb23b7";
    private static final String SECRET_PATH = "userstore";
    private static final String SECRET_KEY = "foo";
    private static final String SECRET_VALUE = "bar";
    private static final String SECRET_KEY_JSON = "json";
    private static final String SECRET_KEY_COMPLEX = "complex";

    private Process vaultProcess;
    private VaultConnector connector;

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder();

    /**
     * Initialize Vault instance with generated configuration and provided file backend.
     * Requires "vault" binary to be in current user's executable path. Not using MLock, so no extended rights required.
     */
    @BeforeEach
    public void setUp(TestInfo testInfo) throws VaultConnectorException, IOException {
        /* Determine, if TLS is required */
        boolean isTls = testInfo.getTags().contains("tls");

        /* Initialize Vault */
        VaultConfiguration config = initializeVault(isTls);
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        /* Initialize connector */
        HTTPVaultConnectorFactory factory = VaultConnectorFactory.httpFactory()
                .withHost(config.getHost())
                .withPort(config.getPort())
                .withTLS(isTls);
        if (isTls)
            factory.withTrustedCA(Paths.get(getClass().getResource("/tls/ca.pem").getPath()));
        connector = factory.build();

        /* Unseal Vault and check result */
        SealResponse sealStatus = connector.unseal(KEY);
        assumeTrue(sealStatus != null);
        assumeFalse(sealStatus.isSealed());
    }

    @AfterEach
    public void tearDown() {
        if (vaultProcess != null && vaultProcess.isAlive())
            vaultProcess.destroy();
    }

    /**
     * Test sealing and unsealing Vault.
     */
    @Test
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
            sealStatus = connector.unseal(KEY);
            assertThat("Vault not unsealed", sealStatus.isSealed(), is(false));
        } catch (VaultConnectorException e) {
            fail("Sealing failed");
        }
    }

    /**
     * Test health status
     */
    @Test
    public void healthTest() {
        HealthResponse res = null;
        try {
            res = connector.getHealth();
        } catch (VaultConnectorException e) {
            fail("Retrieving health status failed: " + e.getMessage());
        }
        assertThat("Health response should be set", res, is(notNullValue()));
        assertThat("Unexpected version", res.getVersion(), is(VAULT_VERISON));
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
     * Test listing of authentication backends
     */
    @Test
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
     * Test authentication using token.
     */
    @Test
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
     * Test authentication using username and password.
     */
    @Test
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
     * App-ID authentication roundtrip.
     */
    @Test
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

    /**
     * App-ID authentication roundtrip.
     */
    @Test
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
     * Test creation of a new AppRole.
     */
    @Test
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
        AppRole role = new AppRoleBuilder(roleName).build();

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

    /**
     * Test listing of AppRole roles and secrets.
     */
    @Test
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
     * Test reading of secrets.
     */
    @Test
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

    /**
     * Test revocation of secrets.
     */
    @Test
    public void createTokenTest() {
        authRoot();
        assumeTrue(connector.isAuthorized());

        /* Create token */
        Token token = new TokenBuilder()
                .withId("test-id")
                .withDisplayName("test name")
                .build();

        /* Create token */
        try {
            AuthResponse res = connector.createToken(token);
            assertThat("No result given.", res, is(notNullValue()));
            assertThat("Token creation returned warnings.", res.getWarnings(), is(nullValue()));
            assertThat("Invalid token ID returned.", res.getAuth().getClientToken(), is("test-id"));
            assertThat("Invalid number of policies returned.", res.getAuth().getPolicies(), hasSize(1));
            assertThat("Root policy not inherited.", res.getAuth().getPolicies(), contains("root"));
            assertThat("Metadata unexpected.", res.getAuth().getMetadata(), is(nullValue()));
            assertThat("Root token should not be renewable", res.getAuth().isRenewable(), is(false));
        } catch (VaultConnectorException e) {
            fail("Secret written to inaccessible path.");
        }

        /* Create token with attributes */
        token = new TokenBuilder()
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
        token = new TokenBuilder()
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

    /**
     * Test TLS connection with custom certificate chain.
     */
    @Test
    @Tag("tls")
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
     * Test closing the connector.
     */
    @Test
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

    /**
     * Initialize Vault with resource datastore and generated configuration.
     *
     * @param tls use TLS
     * @return Vault Configuration
     * @throws IllegalStateException on error
     */
    private VaultConfiguration initializeVault(boolean tls) throws IllegalStateException, IOException {
        File dataDir = tmpDir.newFolder();
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
            configFile = tmpDir.newFile("vault.conf");
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
