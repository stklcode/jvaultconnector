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

import com.github.stefanbirkner.systemlambda.SystemLambda;
import de.stklcode.jvault.connector.exception.ConnectionException;
import de.stklcode.jvault.connector.exception.TlsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

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
    private static final String VAULT_ADDR_2 = "http://localhost";
    private static final String VAULT_ADDR_3 = "https://localhost/vault/";
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
            .withTimeout(Duration.ofMillis(5678))
            .withNumberOfRetries(9);
        connector = builder.build();

        assertEquals("http://vault2.example.com:1234/foo/", getRequestHelperPrivate(connector, "baseURL"), "URL not set correctly");
        assertNull(getRequestHelperPrivate(connector, "trustedCaCert"), "Trusted CA cert set when no cert provided");
        assertEquals(9, getRequestHelperPrivate(connector, "retries"), "Unexpected number of retries");
        assertEquals(Duration.ofMillis(5678), getRequestHelperPrivate(connector, "timeout"), "Number timeout value");
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
        builder = assertDoesNotThrow(() -> HTTPVaultConnector.builder().withPort(null), "Port number NULL should not throw an exception");
        assertNull(builder.getPort(), "Port number NULL should be passed through");
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
        withVaultEnv(VAULT_ADDR_2, null, null, null).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                () -> HTTPVaultConnector.builder().fromEnv(),
                "Factory creation from minimal environment failed"
            );
            assertEquals(VAULT_ADDR_2 + "/v1/", getRequestHelperPrivate(builder.build(), "baseURL"), "URL without port not set correctly");
            return null;
        });
        withVaultEnv(VAULT_ADDR_3, null, null, null).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                () -> HTTPVaultConnector.builder().fromEnv(),
                "Factory creation from minimal environment failed"
            );
            assertEquals(VAULT_ADDR_3, getRequestHelperPrivate(builder.build(), "baseURL"), "URL with custom path not set correctly");
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

    /**
     * Test CA certificate handling from environment variables
     */
    @Test
    void testCertificateFromEnv() throws Exception {
        // From direct PEM content
        String pem = Files.readString(Paths.get(getClass().getResource("/tls/ca.pem").toURI()));
        AtomicReference<Object> certFromPem = new AtomicReference<>();
        withVaultEnv(VAULT_ADDR, pem, null, null).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                () -> HTTPVaultConnector.builder().fromEnv(),
                "Builder with PEM certificate from environment failed"
            );
            HTTPVaultConnector connector = builder.build();

            certFromPem.set(getRequestHelperPrivate(connector, "trustedCaCert"));
            assertNotNull(certFromPem.get(), "Trusted CA cert from PEM not set");

            return null;
        });

        // From file path
        String file = Paths.get(getClass().getResource("/tls/ca.pem").toURI()).toString();
        AtomicReference<Object> certFromFile = new AtomicReference<>();
        withVaultEnv(VAULT_ADDR, file, null, null).execute(() -> {
            HTTPVaultConnectorBuilder builder = assertDoesNotThrow(
                () -> HTTPVaultConnector.builder().fromEnv(),
                "Builder with certificate path from environment failed"
            );
            HTTPVaultConnector connector = builder.build();

            certFromFile.set(getRequestHelperPrivate(connector, "trustedCaCert"));
            assertNotNull(certFromFile.get(), "Trusted CA cert from file not set");

            return null;
        });

        assertEquals(certFromPem.get(), certFromFile.get(), "Certificates from PEM and file should be equal");

        // Non-existing path CA certificate path
        String doesNotExist = tempDir.toString() + "/doesnotexist";
        withVaultEnv(VAULT_ADDR, doesNotExist, VAULT_MAX_RETRIES.toString(), null).execute(() -> {
            TlsException e = assertThrows(
                TlsException.class,
                () -> HTTPVaultConnector.builder().fromEnv(),
                "Creation with unknown cert path failed"
            );
            assertEquals(doesNotExist, assertInstanceOf(NoSuchFileException.class, e.getCause()).getFile());

            return null;
        });
    }

    /**
     * Test reading the client timeout from {@code VAULT_CLIENT_TIMEOUT}.
     */
    @Test
    void testFromEnvTimeout() throws Exception {
        // Not set: default timeout.
        withVaultEnv(VAULT_ADDR, null, null, null).and("VAULT_CLIENT_TIMEOUT", null).execute(() -> {
            var connector = HTTPVaultConnector.builder().fromEnv().build();
            assertEquals(HTTPVaultConnectorBuilder.DEFAULT_TIMEOUT, getRequestHelperPrivate(connector, "timeout"), "Default timeout expected");
            return null;
        });

        // Plain seconds.
        withVaultEnv(VAULT_ADDR, null, null, null).and("VAULT_CLIENT_TIMEOUT", "30").execute(() -> {
            var connector = HTTPVaultConnector.builder().fromEnv().build();
            assertEquals(Duration.ofSeconds(30), getRequestHelperPrivate(connector, "timeout"), "Timeout not set correctly");
            assertEquals(Duration.ofSeconds(30), getRequestHelperPrivate(connector, "connectTimeout"), "Connect timeout should default to timeout");
            return null;
        });

        // Go duration.
        withVaultEnv(VAULT_ADDR, null, null, null).and("VAULT_CLIENT_TIMEOUT", "1m30s").execute(() -> {
            var connector = HTTPVaultConnector.builder().fromEnv().build();
            assertEquals(Duration.ofSeconds(90), getRequestHelperPrivate(connector, "timeout"), "Timeout not set correctly");
            return null;
        });

        // Zero disables the timeout.
        withVaultEnv(VAULT_ADDR, null, null, null).and("VAULT_CLIENT_TIMEOUT", "0").execute(() -> {
            var connector = HTTPVaultConnector.builder().fromEnv().build();
            assertNull(getRequestHelperPrivate(connector, "timeout"), "Timeout should be disabled");
            assertNull(getRequestHelperPrivate(connector, "connectTimeout"), "Connect timeout should be disabled");
            return null;
        });

        // Malformed value is ignored.
        withVaultEnv(VAULT_ADDR, null, null, null).and("VAULT_CLIENT_TIMEOUT", "soon").execute(() -> {
            var connector = HTTPVaultConnector.builder().withTimeout(Duration.ofSeconds(5)).fromEnv().build();
            assertEquals(Duration.ofSeconds(5), getRequestHelperPrivate(connector, "timeout"), "Malformed value should be ignored");
            return null;
        });
    }

    @ParameterizedTest
    @MethodSource("durations")
    void testParseDuration(String value, Duration expected) {
        assertEquals(expected, HTTPVaultConnectorBuilder.parseDuration(value));
    }

    static Stream<Arguments> durations() {
        return Stream.of(
            Arguments.of("0", Duration.ZERO),
            Arguments.of("60", Duration.ofSeconds(60)),
            Arguments.of("0s", Duration.ZERO),
            Arguments.of("45s", Duration.ofSeconds(45)),
            Arguments.of("500ms", Duration.ofMillis(500)),
            Arguments.of("1.5s", Duration.ofMillis(1500)),
            Arguments.of("2m", Duration.ofMinutes(2)),
            Arguments.of("1h2m3s", Duration.ofSeconds(3723)),
            Arguments.of("250us", Duration.ofNanos(250_000)),
            Arguments.of("10ns", Duration.ofNanos(10)),
            Arguments.of("", null),
            Arguments.of("-5", null),
            Arguments.of("-5s", null),
            Arguments.of("1.5", null),
            Arguments.of("5x", null),
            Arguments.of("s", null),
            Arguments.of("10s foo", null),
            Arguments.of("99999999999h", null)
        );
    }

    private SystemLambda.WithEnvironmentVariables withVaultEnv(String vaultAddr, String vaultCacert, String vaultMaxRetries, String vaultToken) {
        return withEnvironmentVariable("VAULT_ADDR", vaultAddr)
            .and("VAULT_CACERT", vaultCacert)
            .and("VAULT_MAX_RETRIES", vaultMaxRetries)
            .and("VAULT_TOKEN", vaultToken);
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
