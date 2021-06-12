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

package de.stklcode.jvault.connector;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import de.stklcode.jvault.connector.exception.ConnectionException;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.exception.PermissionDeniedException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JUnit test for HTTP Vault connector.
 * This test suite contains tests that do not require connection to an actual Vault instance.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
class HTTPVaultConnectorOfflineTest {
    private static WireMockServer wireMock;

    @BeforeAll
    static void prepare() {
        // Initialize HTTP mock.
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        WireMock.configureFor("localhost", wireMock.port());
    }

    @AfterAll
    static void tearDown() {
        wireMock.stop();
        wireMock = null;
    }

    /**
     * Test exceptions thrown during request.
     */
    @Test
    void requestExceptionTest() throws IOException, URISyntaxException {
        HTTPVaultConnector connector = HTTPVaultConnector.builder(wireMock.url("/")).withTimeout(250).build();

        // Test invalid response code.
        final int responseCode = 400;
        mockHttpResponse(responseCode, "", "application/json");
        VaultConnectorException e = assertThrows(
                InvalidResponseException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Invalid response code"));
        assertThat("Unexpected status code in exception", ((InvalidResponseException) e).getStatusCode(), is(responseCode));
        assertThat("Response message where none was expected", ((InvalidResponseException) e).getResponse(), is(nullValue()));

        // Simulate permission denied response.
        mockHttpResponse(responseCode, "{\"errors\":[\"permission denied\"]}", "application/json");
        assertThrows(
                PermissionDeniedException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );

        // Test exception thrown during request.
        try (ServerSocket s = new ServerSocket(0)) {
            connector = HTTPVaultConnector.builder("http://localst:" + s.getLocalPort() + "/").withTimeout(250).build();
        }
        e = assertThrows(
                ConnectionException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Unable to connect to Vault server"));
        assertThat("Unexpected cause", e.getCause(), instanceOf(IOException.class));

        // Now simulate a failing request that succeeds on second try.
        connector = HTTPVaultConnector.builder(wireMock.url("/")).withNumberOfRetries(1).withTimeout(250).build();

        WireMock.stubFor(
                WireMock.any(anyUrl())
                        .willReturn(aResponse().withStatus(500))
                        .willReturn(aResponse().withStatus(500))
                        .willReturn(aResponse().withStatus(500))
                        .willReturn(aResponse().withStatus(200).withBody("{}").withHeader("Content-Type", "application/json"))
        );
        assertDoesNotThrow(connector::getHealth, "Request failed unexpectedly");
    }

    /**
     * Test constructors of the {@link HTTPVaultConnector} class.
     */
    @Test
    void constructorTest() throws IOException, CertificateException, URISyntaxException {
        final String url = "https://vault.example.net/test/";
        final String hostname = "vault.example.com";
        final Integer port = 1337;
        final String prefix = "/custom/prefix/";
        final int retries = 42;
        final String expectedNoTls = "http://" + hostname + ":8200/v1/";
        final String expectedCustomPort = "https://" + hostname + ":" + port + "/v1/";
        final String expectedCustomPrefix = "https://" + hostname + ":" + port + prefix;
        X509Certificate trustedCaCert;

        try (InputStream is = getClass().getResourceAsStream("/tls/ca.pem")) {
            trustedCaCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }

        // Most basic constructor expects complete URL.
        HTTPVaultConnector connector = HTTPVaultConnector.builder(url).build();
        assertThat("Unexpected base URL", getRequestHelperPrivate(connector, "baseURL"), is(url));

        // Now override TLS usage.
        connector = HTTPVaultConnector.builder().withHost(hostname).withoutTLS().build();
        assertThat("Unexpected base URL with TLS disabled", getRequestHelperPrivate(connector, "baseURL"), is(expectedNoTls));

        // Specify custom port.
        connector = HTTPVaultConnector.builder().withHost(hostname).withTLS().withPort(port).build();
        assertThat("Unexpected base URL with custom port", getRequestHelperPrivate(connector, "baseURL"), is(expectedCustomPort));

        // Specify custom prefix.
        connector = HTTPVaultConnector.builder().withHost(hostname).withTLS().withPort(port).withPrefix(prefix).build();
        assertThat("Unexpected base URL with custom prefix", getRequestHelperPrivate(connector, "baseURL"), is(expectedCustomPrefix));
        assertThat("Trusted CA cert set, but not specified", getRequestHelperPrivate(connector, "trustedCaCert"), is(nullValue()));

        // Specify number of retries.
        connector = HTTPVaultConnector.builder(url).withTrustedCA(trustedCaCert).withNumberOfRetries(retries).build();
        assertThat("Number of retries not set correctly", getRequestHelperPrivate(connector, "retries"), is(retries));

        // Test TLS version (#22).
        assertThat("TLS version should be 1.2 if not specified", getRequestHelperPrivate(connector, "tlsVersion"), is("TLSv1.2"));
        // Now override.
        connector = HTTPVaultConnector.builder(url).withTrustedCA(trustedCaCert).withNumberOfRetries(retries).withTLS("TLSv1.1").build();
        assertThat("Overridden TLS version 1.1 not correct", getRequestHelperPrivate(connector, "tlsVersion"), is("TLSv1.1"));
    }

    /**
     * This test is designed to test exceptions caught and thrown by seal-methods if Vault is not reachable.
     */
    @Test
    void sealExceptionTest() throws IOException, URISyntaxException {
        // Simulate no connection.
        VaultConnector connector;
        try (ServerSocket s = new ServerSocket(0)) {
            connector = HTTPVaultConnector.builder("http://localst:" + s.getLocalPort()).withTimeout(250).build();
        }
        ConnectionException e = assertThrows(
                ConnectionException.class,
                connector::sealStatus,
                "Querying seal status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Unable to connect to Vault server"));
    }

    /**
     * This test is designed to test exceptions caught and thrown by seal-methods if Vault is not reachable.
     */
    @Test
    void healthExceptionTest() throws IOException, URISyntaxException {
        // Simulate no connection.
        HTTPVaultConnector connector;
        try (ServerSocket s = new ServerSocket(0)) {
            connector = HTTPVaultConnector.builder("http://localhost:" + s.getLocalPort() + "/").withTimeout(250).build();
        }
        ConnectionException e = assertThrows(
                ConnectionException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Unable to connect to Vault server"));
    }

    /**
     * Test behavior on unparsable responses.
     */
    @Test
    void parseExceptionTest() throws URISyntaxException {
        HTTPVaultConnector connector = HTTPVaultConnector.builder(wireMock.url("/")).withTimeout(250).build();
        // Mock authorization.
        setPrivate(connector, "authorized", true);
        // Mock response.
        mockHttpResponse(200, "invalid", "application/json");

        // Now test the methods.
        assertParseError(connector::sealStatus, "sealStatus() succeeded on invalid instance");
        assertParseError(() -> connector.unseal("key"), "unseal() succeeded on invalid instance");
        assertParseError(connector::getHealth, "getHealth() succeeded on invalid instance");
        assertParseError(connector::getAuthBackends, "getAuthBackends() succeeded on invalid instance");
        assertParseError(() -> connector.authToken("token"), "authToken() succeeded on invalid instance");
        assertParseError(() -> connector.lookupAppRole("roleName"), "lookupAppRole() succeeded on invalid instance");
        assertParseError(() -> connector.getAppRoleID("roleName"), "getAppRoleID() succeeded on invalid instance");
        assertParseError(() -> connector.createAppRoleSecret("roleName"), "createAppRoleSecret() succeeded on invalid instance");
        assertParseError(() -> connector.lookupAppRoleSecret("roleName", "secretID"), "lookupAppRoleSecret() succeeded on invalid instance");
        assertParseError(connector::listAppRoles, "listAppRoles() succeeded on invalid instance");
        assertParseError(() -> connector.listAppRoleSecrets("roleName"), "listAppRoleSecrets() succeeded on invalid instance");
        assertParseError(() -> connector.read("key"), "read() succeeded on invalid instance");
        assertParseError(() -> connector.list("path"), "list() succeeded on invalid instance");
        assertParseError(() -> connector.renew("leaseID"), "renew() succeeded on invalid instance");
        assertParseError(() -> connector.lookupToken("token"), "lookupToken() succeeded on invalid instance");
    }

    private void assertParseError(Executable executable, String message) {
        InvalidResponseException e = assertThrows(InvalidResponseException.class, executable, message);
        assertThat("Unexpected exception message", e.getMessage(), is("Unable to parse response"));
    }

    /**
     * Test requests that expect an empty response with code 204, but receive a 200 body.
     */
    @Test
    void nonEmpty204ResponseTest() throws URISyntaxException {
        HTTPVaultConnector connector = HTTPVaultConnector.builder(wireMock.url("/")).withTimeout(250).build();
        // Mock authorization.
        setPrivate(connector, "authorized", true);
        // Mock response.
        mockHttpResponse(200, "{}", "application/json");

        // Now test the methods expecting a 204.
        assertThrows(
                InvalidResponseException.class,
                () -> connector.registerAppId("appID", "policy", "displayName"),
                "registerAppId() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.registerUserId("appID", "userID"),
                "registerUserId() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.createAppRole("appID", Collections.singletonList("policy")),
                "createAppRole() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.deleteAppRole("roleName"),
                "deleteAppRole() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.setAppRoleID("roleName", "roleID"),
                "setAppRoleID() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.destroyAppRoleSecret("roleName", "secretID"),
                "destroyAppRoleSecret() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.destroyAppRoleSecret("roleName", "secretUD"),
                "destroyAppRoleSecret() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.delete("key"),
                "delete() with 200 response succeeded"
        );

        assertThrows(
                InvalidResponseException.class,
                () -> connector.revoke("leaseID"),
                "destroyAppRoleSecret() with 200 response succeeded"
        );
    }

    private Object getRequestHelperPrivate(HTTPVaultConnector connector, String fieldName) {
        try {
            return getPrivate(getPrivate(connector, "request"), fieldName);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            return null;
        }
    }

    private Object getPrivate(Object target, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = target.getClass().getDeclaredField(fieldName);
        if (field.isAccessible()) {
            return field.get(target);
        }
        field.setAccessible(true);
        Object value = field.get(target);
        field.setAccessible(false);
        return value;
    }

    private void setPrivate(Object target, String fieldName, Object value) {
        try {
            Field field = target.getClass().getDeclaredField(fieldName);
            boolean accessible = field.isAccessible();
            field.setAccessible(true);
            field.set(target, value);
            field.setAccessible(accessible);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            // Should not occur, to be taken care of in test code.
        }
    }

    private void mockHttpResponse(int status, String body, String contentType) {
        WireMock.stubFor(
                WireMock.any(anyUrl()).willReturn(
                        aResponse().withStatus(status).withBody(body).withHeader("Content-Type", contentType)
                )
        );
    }
}
