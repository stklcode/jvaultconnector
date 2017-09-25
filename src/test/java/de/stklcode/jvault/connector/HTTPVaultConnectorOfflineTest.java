/*
 * Copyright 2016-2017 Stefan Kalscheuer
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
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicStatusLine;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.*;

/**
 * JUnit test for HTTP Vault connector.
 * This test suite contains tests that do not require connection to an actual Vault instance.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({HttpClientBuilder.class})
@PowerMockIgnore({"javax.net.ssl.*"})
public class HTTPVaultConnectorOfflineTest {
    private static final String INVALID_URL = "foo:/\\1nv4l1d_UrL";

    @Mock
    private HttpClientBuilder httpMockBuilder;

    @Mock
    private CloseableHttpClient httpMock;

    @Mock
    private CloseableHttpResponse responseMock;

    /**
     * Test exceptions thrown during request.
     */
    @Test
    public void requestExceptionTest() throws IOException {
        HTTPVaultConnector connector = new HTTPVaultConnector("http://127.0.0.1", null, 0, 250);

        // Test invalid response code.
        initHttpMock();
        final int responseCode = 400;
        mockResponse(responseCode, "", ContentType.APPLICATION_JSON);
        try {
            connector.getHealth();
            fail("Querying health status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Invalid response code"));
            assertThat("Unexpected status code in exception", ((InvalidResponseException) e).getStatusCode(), is(responseCode));
            assertThat("Response message where none was expected", ((InvalidResponseException) e).getResponse(), is(nullValue()));
        }

        // Simulate permission denied response.
        mockResponse(responseCode, "{\"errors\":[\"permission denied\"]}", ContentType.APPLICATION_JSON);
        try {
            connector.getHealth();
            fail("Querying health status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(PermissionDeniedException.class));
        }

        // Test exception thrown during request.
        when(httpMock.execute(any())).thenThrow(new IOException("Test Exception"));
        try {
            connector.getHealth();
            fail("Querying health status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Unable to read response"));
            assertThat("Unexpected cause", e.getCause(), instanceOf(IOException.class));
        }

        // Now simulate a failing request that succeeds on second try.
        connector = new HTTPVaultConnector("https://127.0.0.1", null, 1, 250);
        doReturn(responseMock).doReturn(responseMock).when(httpMock).execute(any());
        doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 500, ""))
                .doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 500, ""))
                .doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 500, ""))
                .doReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 200, ""))
                .when(responseMock).getStatusLine();
        when(responseMock.getEntity()).thenReturn(new StringEntity("{}", ContentType.APPLICATION_JSON));

        try {
            connector.getHealth();
        } catch (Exception e) {
            fail("Request failed unexpectedly: " + e.getMessage());
        }
    }

    /**
     * Test constductors of the {@link HTTPVaultConnector} class.
     */
    @Test
    public void constructorTest() throws NoSuchAlgorithmException {
        final String url = "https://vault.example.net/test/";
        final String hostname = "vault.example.com";
        final Integer port = 1337;
        final String prefix = "/custom/prefix/";
        final Integer retries = 42;
        final String expectedNoTls = "http://" + hostname + "/v1/";
        final String expectedCustomPort = "https://" + hostname + ":" + port + "/v1/";
        final String expectedCustomPrefix = "https://" + hostname + ":" + port + prefix;
        final SSLContext sslContext = SSLContext.getInstance("TLS");

        // Most basic constructor expects complete URL.
        HTTPVaultConnector connector = new HTTPVaultConnector(url);
        assertThat("Unexpected base URL", getPrivate(connector, "baseURL"), is(url));

        // Now override TLS usage.
        connector = new HTTPVaultConnector(hostname, false);
        assertThat("Unexpected base URL with TLS disabled", getPrivate(connector, "baseURL"), is(expectedNoTls));

        // Specify custom port.
        connector = new HTTPVaultConnector(hostname, true, port);
        assertThat("Unexpected base URL with custom port", getPrivate(connector, "baseURL"), is(expectedCustomPort));

        // Specify custom prefix.
        connector = new HTTPVaultConnector(hostname, true, port, prefix);
        assertThat("Unexpected base URL with custom prefix", getPrivate(connector, "baseURL"), is(expectedCustomPrefix));
        assertThat("SSL context set, but not specified", getPrivate(connector, "sslContext"), is(nullValue()));

        // Provide custom SSL context.
        connector = new HTTPVaultConnector(hostname, true, port, prefix, sslContext);
        assertThat("Unexpected base URL with custom prefix", getPrivate(connector, "baseURL"), is(expectedCustomPrefix));
        assertThat("SSL context not filled correctly", getPrivate(connector, "sslContext"), is(sslContext));

        // Specify number of retries.
        connector = new HTTPVaultConnector(url, sslContext, retries);
        assertThat("Number of retries not set correctly", getPrivate(connector, "retries"), is(retries));
    }

    /**
     * This test is designed to test exceptions caught and thrown by seal-methods if Vault is not reachable.
     */
    @Test
    public void sealExceptionTest() throws IOException {
        HTTPVaultConnector connector = new HTTPVaultConnector(INVALID_URL);
        try {
            connector.sealStatus();
            fail("Querying seal status succeeded on invalid URL");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidRequestException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Invalid URI format"));
        }

        connector = new HTTPVaultConnector("https://127.0.0.1", null, 0, 250);

        // Simulate NULL response (mock not supplied with data).
        initHttpMock();
        try {
            connector.sealStatus();
            fail("Querying seal status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Response unavailable"));
        }

        // Simulate un-mappable response.
        mockResponse(200, "", ContentType.APPLICATION_JSON);
        try {
            connector.sealStatus();
            fail("Querying seal status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Unable to parse response"));
        }
    }

    /**
     * This test is designed to test exceptions caught and thrown by seal-methods if Vault is not reachable.
     */
    @Test
    public void healthExceptionTest() throws IOException {
        HTTPVaultConnector connector = new HTTPVaultConnector(INVALID_URL);
        try {
            connector.getHealth();
            fail("Querying health status succeeded on invalid URL");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidRequestException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Invalid URI format"));
        }

        connector = new HTTPVaultConnector("https://127.0.0.1", null, 0, 250);

        // Simulate NULL response (mock not supplied with data).
        initHttpMock();
        try {
            connector.getHealth();
            fail("Querying health status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Response unavailable"));
        }

        // Simulate un-mappable response.
        mockResponse(200, "", ContentType.APPLICATION_JSON);
        try {
            connector.getHealth();
            fail("Querying health status succeeded on invalid instance");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Unable to parse response"));
        }
    }

    private Object getPrivate(Object target, String fieldName) {
        try {
            Field field = target.getClass().getDeclaredField(fieldName);
            if (field.isAccessible())
                return field.get(target);
            field.setAccessible(true);
            Object value = field.get(target);
            field.setAccessible(false);
            return value;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            return null;
        }
    }

    private void initHttpMock() {
        mockStatic(HttpClientBuilder.class);
        when(HttpClientBuilder.create()).thenReturn(httpMockBuilder);
        when(httpMockBuilder.setSSLContext(null)).thenReturn(httpMockBuilder);
        when(httpMockBuilder.build()).thenReturn(httpMock);
    }

    private void mockResponse(int status, String body, ContentType type) throws IOException {
        when(httpMock.execute(any())).thenReturn(responseMock);
        when(responseMock.getStatusLine()).thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), status, ""));
        when(responseMock.getEntity()).thenReturn(new StringEntity(body, type));
    }
}
