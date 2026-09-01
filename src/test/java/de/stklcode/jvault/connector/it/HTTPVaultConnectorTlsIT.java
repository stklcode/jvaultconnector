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

import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.response.TokenResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for HTTP Vault connector TLS connection.
 */
@DisplayName("TLS Tests")
@Tag("tls")
class HTTPVaultConnectorTlsIT extends HTTPVaultConnectorITBase {

    /**
     * Test TLS connection with custom certificate chain.
     */
    @Test
    void tlsConnectionTest() {
        assertThrows(
            VaultConnectorException.class,
            () -> connector.authToken("52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6"),
            "Logged in with invalid token"
        );

        TokenResponse res = assertDoesNotThrow(
            () -> connector.authToken(TOKEN_ROOT),
            "Login failed with valid token"
        );
        assertNotNull(res, "Login failed with valid token");
        assertTrue(connector.isAuthorized(), "Login failed with valid token");
    }
}
