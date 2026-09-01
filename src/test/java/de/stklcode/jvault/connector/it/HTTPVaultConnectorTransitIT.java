package de.stklcode.jvault.connector.it;

import de.stklcode.jvault.connector.model.response.TransitResponse;
import org.junit.jupiter.api.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for HTTP Vault connector Transit module.
 */
@DisplayName("Transit Tests")
class HTTPVaultConnectorTransitIT extends HTTPVaultConnectorITBase {

    @Test
    @DisplayName("Transit encryption")
    void transitEncryptTest() {
        Assertions.assertDoesNotThrow(() -> connector.authToken(HTTPVaultConnectorITBase.TOKEN_ROOT));
        Assumptions.assumeTrue(connector.isAuthorized());

        TransitResponse transitResponse = Assertions.assertDoesNotThrow(
            () -> connector.transit().encrypt("my-key", "dGVzdCBtZQ=="),
            "Failed to encrypt via transit"
        );
        assertNotNull(transitResponse.ciphertext());
        assertTrue(transitResponse.ciphertext().startsWith("vault:v1:"));

        transitResponse = Assertions.assertDoesNotThrow(
            () -> connector.transit().encrypt("my-key", "test me".getBytes(UTF_8)),
            "Failed to encrypt binary data via transit"
        );
        assertNotNull(transitResponse.ciphertext());
        assertTrue(transitResponse.ciphertext().startsWith("vault:v1:"));

    }

    @Test
    @DisplayName("Transit decryption")
    void transitDecryptTest() {
        Assertions.assertDoesNotThrow(() -> connector.authToken(HTTPVaultConnectorITBase.TOKEN_ROOT));
        Assumptions.assumeTrue(connector.isAuthorized());

        TransitResponse transitResponse = Assertions.assertDoesNotThrow(
            () -> connector.transit().decrypt("my-key", "vault:v1:1mhLVkBAR2nrFtIkJF/qg57DWfRj0FWgR6tvkGO8XOnL6sw="),
            "Failed to decrypt via transit"
        );

        assertEquals("dGVzdCBtZQ==", transitResponse.plaintext());
    }

    @Test
    @DisplayName("Transit hash")
    void transitHashText() {
        Assertions.assertDoesNotThrow(() -> connector.authToken(HTTPVaultConnectorITBase.TOKEN_ROOT));
        Assumptions.assumeTrue(connector.isAuthorized());

        TransitResponse transitResponse = Assertions.assertDoesNotThrow(
            () -> connector.transit().hash("sha2-512", "dGVzdCBtZQ=="),
            "Failed to hash via transit"
        );

        assertEquals("7677af0ee4effaa9f35e9b1e82d182f79516ab8321786baa23002de7c06851059492dd37d5fc3791f17d81d4b58198d24a6fd8bbd62c42c1c30b371da500f193", transitResponse.sum());

        TransitResponse transitResponseBase64 = Assertions.assertDoesNotThrow(
            () -> connector.transit().hash("sha2-256", "dGVzdCBtZQ==", "base64"),
            "Failed to hash via transit with base64 output"
        );

        assertEquals("5DfYkW7cvGLkfy36cXhqmZcygEy9HpnFNB4WWXKOl1M=", transitResponseBase64.sum());

        transitResponseBase64 = Assertions.assertDoesNotThrow(
            () -> connector.transit().hash("sha2-256", "test me".getBytes(UTF_8), "base64"),
            "Failed to hash binary data via transit"
        );

        assertEquals("5DfYkW7cvGLkfy36cXhqmZcygEy9HpnFNB4WWXKOl1M=", transitResponseBase64.sum());
    }
}
