/*
 * Copyright 2016-2025 Stefan Kalscheuer
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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import de.stklcode.jvault.connector.exception.ConnectionException;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.exception.PermissionDeniedException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit test for HTTP Vault connector.
 * This test suite contains tests that do not require connection to an actual Vault instance.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
@WireMockTest
class HTTPVaultConnectorTest {

    /**
     * Test exceptions thrown during request.
     */
    @Test
    void requestExceptionTest(WireMockRuntimeInfo wireMock) throws IOException, URISyntaxException {
        HTTPVaultConnector connector = HTTPVaultConnector.builder(wireMock.getHttpBaseUrl()).withTimeout(250).build();

        // Test invalid response code.
        final int responseCode = 400;
        mockHttpResponse(responseCode, "", "application/json");
        VaultConnectorException e = assertThrows(
            InvalidResponseException.class,
            connector::getHealth,
            "Querying health status succeeded on invalid instance"
        );
        assertEquals("Invalid response code", e.getMessage(), "Unexpected exception message");
        assertEquals(responseCode, ((InvalidResponseException) e).getStatusCode(), "Unexpected status code in exception");
        assertNull(((InvalidResponseException) e).getResponse(), "Response message where none was expected");

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
        assertEquals("Unable to connect to Vault server", e.getMessage(), "Unexpected exception message");
        assertInstanceOf(IOException.class, e.getCause(), "Unexpected cause");

        // Now simulate a failing request that succeeds on second try.
        connector = HTTPVaultConnector.builder(wireMock.getHttpBaseUrl()).withNumberOfRetries(1).withTimeout(250).build();

        stubFor(
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
        assertEquals(url, getRequestHelperPrivate(connector, "baseURL"), "Unexpected base URL");

        // Now override TLS usage.
        connector = HTTPVaultConnector.builder().withHost(hostname).withoutTLS().build();
        assertEquals(expectedNoTls, getRequestHelperPrivate(connector, "baseURL"), "Unexpected base URL with TLS disabled");

        // Specify custom port.
        connector = HTTPVaultConnector.builder().withHost(hostname).withTLS().withPort(port).build();
        assertEquals(expectedCustomPort, getRequestHelperPrivate(connector, "baseURL"), "Unexpected base URL with custom port");

        // Specify custom prefix.
        connector = HTTPVaultConnector.builder().withHost(hostname).withTLS().withPort(port).withPrefix(prefix).build();
        assertEquals(expectedCustomPrefix, getRequestHelperPrivate(connector, "baseURL"), "Unexpected base URL with custom prefix");
        assertNull(getRequestHelperPrivate(connector, "trustedCaCert"), "Trusted CA cert set, but not specified");

        // Specify number of retries.
        connector = HTTPVaultConnector.builder(url).withTrustedCA(trustedCaCert).withNumberOfRetries(retries).build();
        assertEquals(retries, getRequestHelperPrivate(connector, "retries"), "Number of retries not set correctly");

        // Test TLS version (#22).
        assertEquals("TLSv1.2", getRequestHelperPrivate(connector, "tlsVersion"), "TLS version should be 1.2 if not specified");
        // Now override.
        connector = HTTPVaultConnector.builder(url).withTrustedCA(trustedCaCert).withNumberOfRetries(retries).withTLS("TLSv1.1").build();
        assertEquals("TLSv1.1", getRequestHelperPrivate(connector, "tlsVersion"), "Overridden TLS version 1.1 not correct");
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
        assertEquals("Unable to connect to Vault server", e.getMessage(), "Unexpected exception message");
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
        assertEquals("Unable to connect to Vault server", e.getMessage(), "Unexpected exception message");
    }

    /**
     * Test behavior on unparsable responses.
     */
    @Test
    void parseExceptionTest(WireMockRuntimeInfo wireMock) throws URISyntaxException {
        HTTPVaultConnector connector = HTTPVaultConnector.builder(wireMock.getHttpBaseUrl()).withTimeout(250).build();
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
        assertEquals("Unable to parse response", e.getMessage(), "Unexpected exception message");
    }

    /**
     * Test requests that expect an empty response with code 204, but receive a 200 body.
     */
    @Test
    void nonEmpty204ResponseTest(WireMockRuntimeInfo wireMock) throws URISyntaxException {
        HTTPVaultConnector connector = HTTPVaultConnector.builder(wireMock.getHttpBaseUrl()).withTimeout(250).build();
        // Mock authorization.
        setPrivate(connector, "authorized", true);
        // Mock response.
        mockHttpResponse(200, "{}", "application/json");

        // Now test the methods expecting a 204.
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
        if (field.canAccess(target)) {
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
            boolean accessible = field.canAccess(target);
            field.setAccessible(true);
            field.set(target, value);
            field.setAccessible(accessible);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            // Should not occur, to be taken care of in test code.
        }
    }

    private void mockHttpResponse(int status, String body, String contentType) {
        stubFor(
            WireMock.any(anyUrl()).willReturn(
                aResponse().withStatus(status).withBody(body).withHeader("Content-Type", contentType)
            )
        );
    }
}
