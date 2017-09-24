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
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * JUnit test for HTTP Vault connector.
 * This test suite contains tests that do not require connection to an actual Vault instance.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
public class HTTPVaultConnectorOfflineTest {

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
        HTTPVaultConnector connector = new HTTPVaultConnector("foo:/\\1nv4l1d_UrL");
        try {
            connector.sealStatus();
            fail("Querying seal status succeeded on invalid URL");
        } catch (Exception e) {
            assertThat("Unexpected type of exception", e, instanceOf(InvalidRequestException.class));
            assertThat("Unexpected exception message", e.getMessage(), is("Invalid URI format"));
        }

        // Create socket on free port to ensure no other process is listening on the specified URL.
        try (ServerSocket s = new ServerSocket(0)) {
            connector = new HTTPVaultConnector("https://127.0.0.1:" + s.getLocalPort(), null, 0, 250);
            try {
                connector.sealStatus();
                fail("Querying seal status succeeded on invalid instance");
            } catch (Exception e) {
                assertThat("Unexpected type of exception", e, instanceOf(InvalidResponseException.class));
                assertThat("Unexpected exception message", e.getMessage(), is("Unable to read response"));
            }
        }
    }

    private void fail(String s) {
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
}
