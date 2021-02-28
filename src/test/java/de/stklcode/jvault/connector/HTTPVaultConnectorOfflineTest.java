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

import de.stklcode.jvault.connector.exception.InvalidRequestException;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.exception.PermissionDeniedException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicStatusLine;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * JUnit test for HTTP Vault connector.
 * This test suite contains tests that do not require connection to an actual Vault instance.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
class HTTPVaultConnectorOfflineTest {
    private static final String INVALID_URL = "foo:/\\1nv4l1d_UrL";

    private static MockedStatic<HttpClientBuilder> hcbMock;
    private static CloseableHttpClient httpMock;
    private final CloseableHttpResponse responseMock = mock(CloseableHttpResponse.class);

    @BeforeAll
    static void prepare() {
        // Mock the static HTTPClient creation.
        hcbMock = mockStatic(HttpClientBuilder.class);
        hcbMock.when(HttpClientBuilder::create).thenReturn(new MockedHttpClientBuilder());
    }

     @AfterAll
     static void tearDown() {
         hcbMock.close();
     }

    @BeforeEach
    void init() {
        // Re-initialize HTTP mock to ensure fresh (empty) results.
        httpMock = mock(CloseableHttpClient.class);
    }


    /**
     * Test exceptions thrown during request.
     */
    @Test
    void requestExceptionTest() throws IOException {
        HTTPVaultConnector connector = new HTTPVaultConnector("http://127.0.0.1", null, 0, 250);

        // Test invalid response code.
        final int responseCode = 400;
        mockResponse(responseCode, "", ContentType.APPLICATION_JSON);
        InvalidResponseException e = assertThrows(
                InvalidResponseException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Invalid response code"));
        assertThat("Unexpected status code in exception", ((InvalidResponseException) e).getStatusCode(), is(responseCode));
        assertThat("Response message where none was expected", ((InvalidResponseException) e).getResponse(), is(nullValue()));

        // Simulate permission denied response.
        mockResponse(responseCode, "{\"errors\":[\"permission denied\"]}", ContentType.APPLICATION_JSON);
        assertThrows(
                PermissionDeniedException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );

        // Test exception thrown during request.
        when(httpMock.execute(any())).thenThrow(new IOException("Test Exception"));
        e = assertThrows(
                InvalidResponseException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Unable to read response"));
        assertThat("Unexpected cause", e.getCause(), instanceOf(IOException.class));

        // Now simulate a failing request that succeeds on second try.
        connector = new HTTPVaultConnector("https://127.0.0.1", null, 1, 250);
        doReturn(responseMock).doReturn(responseMock).when(httpMock).execute(any());
        doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 500, ""))
                .doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 500, ""))
                .doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 500, ""))
                .doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 200, ""))
                .when(responseMock).getStatusLine();
        when(responseMock.getEntity()).thenReturn(new StringEntity("{}", ContentType.APPLICATION_JSON));

        assertDoesNotThrow(connector::getHealth, "Request failed unexpectedly");
    }

    /**
     * Test constructors of the {@link HTTPVaultConnector} class.
     */
    @Test
    void constructorTest() throws IOException, CertificateException {
        final String url = "https://vault.example.net/test/";
        final String hostname = "vault.example.com";
        final Integer port = 1337;
        final String prefix = "/custom/prefix/";
        final int retries = 42;
        final String expectedNoTls = "http://" + hostname + "/v1/";
        final String expectedCustomPort = "https://" + hostname + ":" + port + "/v1/";
        final String expectedCustomPrefix = "https://" + hostname + ":" + port + prefix;
        X509Certificate trustedCaCert;

        try (InputStream is = getClass().getResourceAsStream("/tls/ca.pem")) {
            trustedCaCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }

        // Most basic constructor expects complete URL.
        HTTPVaultConnector connector = new HTTPVaultConnector(url);
        assertThat("Unexpected base URL", getRequestHelperPrivate(connector, "baseURL"), is(url));

        // Now override TLS usage.
        connector = new HTTPVaultConnector(hostname, false);
        assertThat("Unexpected base URL with TLS disabled", getRequestHelperPrivate(connector, "baseURL"), is(expectedNoTls));

        // Specify custom port.
        connector = new HTTPVaultConnector(hostname, true, port);
        assertThat("Unexpected base URL with custom port", getRequestHelperPrivate(connector, "baseURL"), is(expectedCustomPort));

        // Specify custom prefix.
        connector = new HTTPVaultConnector(hostname, true, port, prefix);
        assertThat("Unexpected base URL with custom prefix", getRequestHelperPrivate(connector, "baseURL"), is(expectedCustomPrefix));
        assertThat("Trusted CA cert set, but not specified", getRequestHelperPrivate(connector, "trustedCaCert"), is(nullValue()));

        // Provide custom SSL context.
        connector = new HTTPVaultConnector(hostname, true, port, prefix, trustedCaCert);
        assertThat("Unexpected base URL with custom prefix", getRequestHelperPrivate(connector, "baseURL"), is(expectedCustomPrefix));
        assertThat("Trusted CA cert not filled correctly", getRequestHelperPrivate(connector, "trustedCaCert"), is(trustedCaCert));

        // Specify number of retries.
        connector = new HTTPVaultConnector(url, trustedCaCert, retries);
        assertThat("Number of retries not set correctly", getRequestHelperPrivate(connector, "retries"), is(retries));

        // Test TLS version (#22).
        assertThat("TLS version should be 1.2 if not specified", getRequestHelperPrivate(connector, "tlsVersion"), is("TLSv1.2"));
        // Now override.
        connector = new HTTPVaultConnector(url, trustedCaCert, retries, null, "TLSv1.1");
        assertThat("Overridden TLS version 1.1 not correct", getRequestHelperPrivate(connector, "tlsVersion"), is("TLSv1.1"));
    }

    /**
     * This test is designed to test exceptions caught and thrown by seal-methods if Vault is not reachable.
     */
    @Test
    void sealExceptionTest() {
        HTTPVaultConnector connector = new HTTPVaultConnector(INVALID_URL);
        VaultConnectorException e = assertThrows(
                InvalidRequestException.class,
                connector::sealStatus,
                "Querying seal status succeeded on invalid URL"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Invalid URI format"));

        // Simulate NULL response (mock not supplied with data).
        connector = new HTTPVaultConnector("https://127.0.0.1", null, 0, 250);
        e = assertThrows(
                InvalidResponseException.class,
                connector::sealStatus,
                "Querying seal status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Response unavailable"));
    }

    /**
     * This test is designed to test exceptions caught and thrown by seal-methods if Vault is not reachable.
     */
    @Test
    void healthExceptionTest() {
        HTTPVaultConnector connector = new HTTPVaultConnector(INVALID_URL);
        VaultConnectorException e = assertThrows(
                InvalidRequestException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid URL"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Invalid URI format"));

        // Simulate NULL response (mock not supplied with data).
        connector = new HTTPVaultConnector("https://127.0.0.1", null, 0, 250);
        e = assertThrows(
                InvalidResponseException.class,
                connector::getHealth,
                "Querying health status succeeded on invalid instance"
        );
        assertThat("Unexpected exception message", e.getMessage(), is("Response unavailable"));
    }

    /**
     * Test behavior on unparsable responses.
     */
    @Test
    void parseExceptionTest() throws IOException {
        HTTPVaultConnector connector = new HTTPVaultConnector("https://127.0.0.1", null, 0, 250);
        // Mock authorization.
        setPrivate(connector, "authorized", true);
        // Mock response.
        mockResponse(200, "invalid", ContentType.APPLICATION_JSON);

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
    void nonEmpty204ResponseTest() throws IOException {
        HTTPVaultConnector connector = new HTTPVaultConnector("https://127.0.0.1", null, 0, 250);
        // Mock authorization.
        setPrivate(connector, "authorized", true);
        // Mock response.
        mockResponse(200, "{}", ContentType.APPLICATION_JSON);

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

    private void mockResponse(int status, String body, ContentType type) throws IOException {
        when(httpMock.execute(any())).thenReturn(responseMock);
        when(responseMock.getStatusLine()).thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), status, ""));
        when(responseMock.getEntity()).thenReturn(new StringEntity(body, type));
    }

    /**
     * Mocked {@link HttpClientBuilder} that always returns the mocked client.
     */
    private static class MockedHttpClientBuilder extends HttpClientBuilder {
        @Override
        public CloseableHttpClient build() {
            return httpMock;
        }
    }

}
