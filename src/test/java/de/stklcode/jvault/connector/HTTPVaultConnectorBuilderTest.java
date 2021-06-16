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

import com.github.stefanbirkner.systemlambda.SystemLambda;
import de.stklcode.jvault.connector.exception.ConnectionException;
import de.stklcode.jvault.connector.exception.TlsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit test for HTTP Vault connector factory
 *
 * @author Stefan Kalscheuer
 * @since 0.8.0
 */
class HTTPVaultConnectorBuilderTest {
    private static final String VAULT_ADDR = "https://localhost:8201";
    private static final Integer VAULT_MAX_RETRIES = 13;
    private static final String VAULT_TOKEN = "00001111-2222-3333-4444-555566667777";

    @TempDir
    File tempDir;

    /**
     * Test the builder.
     */
    @Test
    void builderTest() throws Exception {
        // Minimal configuration.
        HTTPVaultConnector connector = HTTPVaultConnector.builder().withHost("vault.example.com").build();

        assertEquals("https://vault.example.com:8200/v1/", getRequestHelperPrivate(connector, "baseURL"), "URL not set correctly");
        assertNull(getRequestHelperPrivate(connector, "trustedCaCert"), "Trusted CA cert set when no cert provided");
        assertEquals(0, getRequestHelperPrivate(connector, "retries"), "Number of retries unexpectedly set");

        // Specify all options.
        HTTPVaultConnectorBuilder builder = HTTPVaultConnector.builder()
                .withHost("vault2.example.com")
                .withoutTLS()
                .withPort(1234)
                .withPrefix("/foo/")
                .withTimeout(5678)
                .withNumberOfRetries(9);
        connector = builder.build();

        assertEquals("http://vault2.example.com:1234/foo/", getRequestHelperPrivate(connector, "baseURL"), "URL not set correctly");
        assertNull(getRequestHelperPrivate(connector, "trustedCaCert"), "Trusted CA cert set when no cert provided");
        assertEquals(9, getRequestHelperPrivate(connector, "retries"), "Unexpected number of retries");
        assertEquals(5678, getRequestHelperPrivate(connector, "timeout"), "Number timeout value");
        assertThrows(ConnectionException.class, builder::buildAndAuth, "Immediate authentication should throw exception without token");

        // Initialization from URL.
        assertThrows(
                URISyntaxException.class,
                () -> HTTPVaultConnector.builder().withBaseURL("foo:/\\1nv4l1d_UrL"),
                "Initialization from invalid URL should fail"
        );
        connector = assertDoesNotThrow(
                () -> HTTPVaultConnector.builder().withBaseURL("https://vault3.example.com:5678/bar/").build(),
                "Initialization from valid URL should not fail"
        );
        assertEquals("https://vault3.example.com:5678/bar/", getRequestHelperPrivate(connector, "baseURL"), "URL not set correctly");

        // Port numbers.
        assertThrows(IllegalArgumentException.class, () -> HTTPVaultConnector.builder().withPort(65536), "Too large port number should throw an exception");
        assertThrows(IllegalArgumentException.class, () -> HTTPVaultConnector.builder().withPort(0), "Port number 0 should throw an exception");
        builder = assertDoesNotThrow(() -> HTTPVaultConnector.builder().withPort(-1), "Port number -1 should not throw an exception");
        assertNull(builder.getPort(), "Port number -1 should be omitted");
    }

    /**
     * Test building from environment variables
     */
    @Test
    void testFromEnv() throws Exception {
        // Provide address only should be enough.
        withVaultEnv(VAULT_ADDR, null, null, null).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                    () -> HTTPVaultConnector.builder().fromEnv(),
                    "Factory creation from minimal environment failed"
            );
            HTTPVaultConnector connector = builder.build();

            assertEquals(VAULT_ADDR + "/v1/", getRequestHelperPrivate(connector, "baseURL"), "URL not set correctly");
            assertNull(getRequestHelperPrivate(connector, "trustedCaCert"), "Trusted CA cert set when no cert provided");
            assertEquals(0, getRequestHelperPrivate(connector, "retries"), "Non-default number of retries, when none set");

            return null;
        });

        // Provide address and number of retries.
        withVaultEnv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), null).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                    () -> HTTPVaultConnector.builder().fromEnv(),
                    "Factory creation from environment failed"
            );
            HTTPVaultConnector connector = builder.build();

            assertEquals(VAULT_ADDR + "/v1/", getRequestHelperPrivate(connector, "baseURL"), "URL not set correctly");
            assertNull(getRequestHelperPrivate(connector, "trustedCaCert"), "Trusted CA cert set when no cert provided");
            assertEquals(VAULT_MAX_RETRIES, getRequestHelperPrivate(connector, "retries"), "Number of retries not set correctly");

            return null;
        });

        // Provide CA certificate.
        String VAULT_CACERT = tempDir.toString() + "/doesnotexist";
        withVaultEnv(VAULT_ADDR, VAULT_CACERT, VAULT_MAX_RETRIES.toString(), null).execute(() -> {
            TlsException e = assertThrows(
                    TlsException.class,
                    () -> HTTPVaultConnector.builder().fromEnv(),
                    "Creation with unknown cert path failed"
            );
            assertTrue(e.getCause() instanceof NoSuchFileException);
            assertEquals(VAULT_CACERT, ((NoSuchFileException) e.getCause()).getFile());

            return null;
        });

        // Automatic authentication.
        withVaultEnv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), VAULT_TOKEN).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                    () -> HTTPVaultConnector.builder().fromEnv(),
                    "Factory creation from minimal environment failed"
            );
            assertEquals(VAULT_TOKEN, getPrivate(builder, "token"), "Token not set correctly");

            return null;
        });

        // Invalid URL.
        withVaultEnv("This is not a valid URL!", null, VAULT_MAX_RETRIES.toString(), VAULT_TOKEN).execute(() -> {
            assertThrows(
                    ConnectionException.class,
                    () -> HTTPVaultConnector.builder().fromEnv(),
                    "Invalid URL from environment should raise an exception"
            );

            return null;
        });
    }

    private SystemLambda.WithEnvironmentVariables withVaultEnv(String vault_addr, String vault_cacert, String vault_max_retries, String vault_token) {
        return withEnvironmentVariable("VAULT_ADDR", vault_addr)
                .and("VAULT_CACERT", vault_cacert)
                .and("VAULT_MAX_RETRIES", vault_max_retries)
                .and("VAULT_TOKEN", vault_token);
    }

    private Object getRequestHelperPrivate(HTTPVaultConnector connector, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        return getPrivate(getPrivate(connector, "request"), fieldName);
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
}
