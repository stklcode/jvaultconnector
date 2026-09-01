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

package de.stklcode.jvault.connector.it;

import de.stklcode.jvault.connector.exception.InvalidRequestException;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.exception.PermissionDeniedException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.response.SecretResponse;
import de.stklcode.jvault.connector.test.Credentials;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for HTTP Vault connector read/write methods.
 */
@DisplayName("Read/Write Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HTTPVaultConnectorIT extends HTTPVaultConnectorITBase {
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
        Assumptions.assumeTrue(connector.isAuthorized());

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
        SecretResponse res = Assertions.assertDoesNotThrow(
            () -> connector.read(SECRET_PATH + "/" + SECRET_KEY),
            "Valid secret path could not be read"
        );
        assertEquals(SECRET_VALUE, res.get("value"), "Known secret returned invalid value");

        // Try to read accessible path with JSON value.
        res = Assertions.assertDoesNotThrow(
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
        res = Assertions.assertDoesNotThrow(
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
        res = Assertions.assertDoesNotThrow(
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
        Assumptions.assumeTrue(connector.isAuthorized());
        // Try to list secrets from valid path.
        List<String> secrets = Assertions.assertDoesNotThrow(
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
        Assumptions.assumeTrue(connector.isAuthorized());

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
        SecretResponse res = Assertions.assertDoesNotThrow(
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
        Assumptions.assumeTrue(connector.isAuthorized());

        // Write a test secret to vault.
        assertDoesNotThrow(
            () -> connector.write(SECRET_PATH + "/toDelete", "secret content"),
            "Secret written to inaccessible path"
        );
        SecretResponse res = Assertions.assertDoesNotThrow(
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
        Assumptions.assumeTrue(connector.isAuthorized());

        // Write a test secret to vault.
        assertDoesNotThrow(
            () -> connector.write(SECRET_PATH + "/toRevoke", "secret content"),
            "Secret written to inaccessible path"
        );
        SecretResponse res = Assertions.assertDoesNotThrow(
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
