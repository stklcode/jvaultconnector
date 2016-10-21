/*
 * Copyright 2016 Stefan Kalscheuer
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

import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.Token;
import de.stklcode.jvault.connector.model.TokenBuilder;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.test.Credentials;
import de.stklcode.jvault.connector.test.VaultConfiguration;
import de.stklcode.jvault.connector.exception.InvalidRequestException;
import de.stklcode.jvault.connector.exception.PermissionDeniedException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.factory.VaultConnectorFactory;
import de.stklcode.jvault.connector.model.AuthBackend;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

/**
 * JUnit Test for HTTP Vault connector.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class HTTPVaultConnectorTest {
    private static String KEY = "81011a8061e5c028bd0d9503eeba40bd9054b9af0408d080cb24f57405c27a61";
    private static String TOKEN_ROOT = "d1bd50e2-587b-6e68-d80b-a9a507625cb7";
    private static String USER_VALID = "validUser";
    private static String PASS_VALID = "validPass";
    private static String APP_ID = "152AEA38-85FB-47A8-9CBD-612D645BFACA";
    private static String USER_ID = "5ADF8218-D7FB-4089-9E38-287465DBF37E";
    private static String SECRET_PATH = "userstore";
    private static String SECRET_KEY = "foo";
    private static String SECRET_KEY_JSON = "json";
    private static String SECRET_VALUE = "bar";

    private Process vaultProcess;
    private VaultConnector connector;

    @Rule
    public TemporaryFolder tmpDir =  new TemporaryFolder();

    /**
     * Initialize Vault instance with generated configuration and provided file backend.
     * Requires "vault" binary to be in current user's executable path. Not using MLock, so no extended rights required.
     */
    @Before
    public void setUp() {
        /* Initialize Vault */
        VaultConfiguration config = initializeVault();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        /* Initialize connector */
        connector = VaultConnectorFactory.httpFactory()
                .withHost(config.getHost())
                .withPort(config.getPort())
                .withoutTLS()
                .build();
        /* Unseal Vault and check result */
        SealResponse sealStatus = connector.unseal(KEY);
        assumeNotNull(sealStatus);
        assumeFalse(sealStatus.isSealed());
    }

    @After
    public void tearDown() {
        if (vaultProcess != null && vaultProcess.isAlive())
            vaultProcess.destroy();
    }

    /**
     * Test listing of authentication backends
     */
    @Test
    public void authMethodsTest() {
        /* Authenticate as valid user */
        try {
            connector.authToken(TOKEN_ROOT);
        }
        catch(VaultConnectorException ignored) {
        }
        assumeTrue(connector.isAuthorized());

        List<AuthBackend> supportedBackends = null;
        try {
            supportedBackends = connector.getAuthBackends();
        } catch (VaultConnectorException e) {
            fail("Could not list supported auth backends: " + e.getMessage());
        }
        assertThat(supportedBackends.size(), is(3));
        assertThat(supportedBackends, hasItems(AuthBackend.TOKEN, AuthBackend.USERPASS, AuthBackend.APPID));
    }

    /**
     * Test authentication using token.
     */
    @Test
    public void authTokenTest() {
        TokenResponse res;
        try {
            connector.authToken("52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6");
            fail("Logged in with invalid token");
        } catch (VaultConnectorException ignored) {
        }

        try {
            res = connector.authToken(TOKEN_ROOT);
            assertNotNull("Login failed with valid token", res);
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
        try {
            connector.authUserPass("foo", "bar");
            fail("Logged in with invalid credentials");
        }
        catch(VaultConnectorException ignored) {
        }

        try {
            res = connector.authUserPass(USER_VALID, PASS_VALID);
        } catch (VaultConnectorException ignored) {
            fail("Login failed with valid credentials: Exception thrown");
        }
        assertNotNull("Login failed with valid credentials: Response not available", res.getAuth());
        assertThat("Login failed with valid credentials: Connector not authorized", connector.isAuthorized(), is(true));
    }

    /**
     * App-ID authentication roundtrip.
     */
    @Test
    public void authAppIdTest() {
        authRoot();
        assumeTrue(connector.isAuthorized());

        /* Register App-ID */
        try {
            boolean res = connector.registerAppId(APP_ID, "user", "App Name");
            assertThat("Failed to register App-ID", res, is(true));
        }
        catch (VaultConnectorException e) {
            fail("Failed to register App-ID: " + e.getMessage());
        }

        /* Register User-ID */
        try {
            boolean res = connector.registerUserId(APP_ID, USER_ID);
            assertThat("Failed to register App-ID", res, is(true));
        }
        catch (VaultConnectorException e) {
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
     * Test reading of secrets.
     */
    @Test
    public void readSecretTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        /* Try to read path user has no permission to read */
        SecretResponse res = null;
        try {
            res = connector.readSecret("invalid/path");
            fail("Invalid secret path successfully read.");
        } catch (VaultConnectorException e) {
            assertThat(e, instanceOf(PermissionDeniedException.class));
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
    public void writeSecretTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        /* Try to write to null path */
        try {
            boolean res = connector.writeSecret(null, "someValue");
            fail("Secret written to null path.");
        } catch (VaultConnectorException e) {
            assertThat(e, instanceOf(InvalidRequestException.class));
        }
        /* Try to write to invalid path */
        try {
            boolean res = connector.writeSecret("", "someValue");
            fail("Secret written to invalid path.");
        } catch (VaultConnectorException e) {
            assertThat(e, instanceOf(InvalidRequestException.class));
        }
        /* Try to write to a path the user has no access for */
        try {
            boolean res = connector.writeSecret("invalid/path", "someValue");
            fail("Secret written to inaccessible path.");
        } catch (VaultConnectorException e) {
            assertThat(e, instanceOf(PermissionDeniedException.class));
        }
        /* Perform a valid write/read roundtrip to valid path. Also check UTF8-encoding. */
        try {
            boolean res = connector.writeSecret(SECRET_PATH + "/temp", "Abc123äöü,!");
            assertThat("Secret could not be written to valid path.", res, is(true));
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
    public void deleteTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        /* Write a test secret to vault */
        try {
            boolean res = connector.writeSecret(SECRET_PATH + "/toDelete", "secret content");
            assumeThat("Secret could not be written path.", res, is(true));
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
            boolean deleted = connector.deleteSecret(SECRET_PATH + "/toDelete");
            assertThat("Revocation of secret faiked.", deleted, is(true));
        } catch (VaultConnectorException e) {
            fail("Revocation threw unexpected exception.");
        }

        /* Try to read again */
        try {
            connector.readSecret(SECRET_PATH + "/toDelete");
            fail("Successfully read deleted secret.");
        } catch (VaultConnectorException e) {
            assertThat(e, is(instanceOf(InvalidResponseException.class)));
            assertThat(((InvalidResponseException)e).getStatusCode(), is(404));
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
            boolean res = connector.writeSecret(SECRET_PATH + "/toRevoke", "secret content");
            assumeThat("Secret could not be written path.", res, is(true));
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
            boolean revoked = connector.revoke(SECRET_PATH + "/toRevoke");
            assertThat("Revocation of secret faiked.", revoked, is(true));
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

        /* Overwrite token */
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
            AuthResponse res = connector.createToken(token);
            assertThat("Invalid token ID returned.", res.getAuth().getClientToken(), is("test-id2"));
            assertThat("Invalid number of policies returned.", res.getAuth().getPolicies(), hasSize(3));
            assertThat("Policies not returned as expected.", res.getAuth().getPolicies(), contains("default", "pol1", "pol2"));
            assertThat("Old policy not overwritten.", res.getAuth().getPolicies(), not(contains("testpolicy")));
            assertThat("Metadata not given.", res.getAuth().getMetadata(), is(notNullValue()));
            assertThat("Metadata not correct.", res.getAuth().getMetadata().get("test"), is("success"));
            assertThat("Metadata not correct.", res.getAuth().getMetadata().get("key"), is("value"));
            assertThat("Old metadata not overwritten.", res.getAuth().getMetadata().get("foo"), is(nullValue()));
            assertThat("TTL not set correctly", res.getAuth().getLeaseDuration(), is(1234));
            assertThat("Token should be renewable", res.getAuth().isRenewable(), is(true));
        } catch (VaultConnectorException e) {
            fail("Secret written to inaccessible path.");
        }
    }

    /**
     * Initialize Vault with resource datastore and generated configuration.
     * @return  Vault Configuration
     * @throws IllegalStateException on error
     */
    private VaultConfiguration initializeVault() throws IllegalStateException {
        String dataResource = getClass().getResource("/data_dir").getPath();

        /* Generate vault local unencrypted configuration */
        VaultConfiguration config = new VaultConfiguration()
                .withHost("127.0.0.1")
                .withPort(getFreePort())
                .withDataLocation(dataResource)
                .disableMlock();

        /* Write configuration file */
        BufferedWriter bw = null;
        File configFile = null;
        try {
            configFile = tmpDir.newFile("vault.conf");
            bw = new BufferedWriter(new FileWriter(configFile));
            bw.write(config.toString());
        }
        catch (IOException e) {
            e.printStackTrace();
            throw new IllegalStateException("Unable to generate config file.");
        }
        finally {
            try {
                if (bw != null)
                    bw.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }

        /* Start vault process */
        try {
            vaultProcess = Runtime.getRuntime().exec("vault server -config " + configFile.toString());
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalStateException("Unable to start vault. Make sure vault binary is in your executable path.");
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
        }
        catch(VaultConnectorException ignored) {
        }
    }

    /**
     * Authenticate with user credentials.
     */
    private void authUser() {
        try {
            connector.authUserPass(USER_VALID, PASS_VALID);
        }
        catch(VaultConnectorException ignored) {
        }
    }

    /**
     * Find and return a free TCP port.
     * @return  port number
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
}
