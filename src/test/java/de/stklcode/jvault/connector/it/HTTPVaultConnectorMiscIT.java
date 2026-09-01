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

import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.response.AuthResponse;
import de.stklcode.jvault.connector.model.response.HealthResponse;
import de.stklcode.jvault.connector.model.response.SealResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for HTTP Vault connector miscellaneous operations.
 */
@DisplayName("Misc Tests")
class HTTPVaultConnectorMiscIT extends HTTPVaultConnectorITBase {

    /**
     * Test listing of authentication backends
     */
    @Test
    @DisplayName("List auth methods")
    void authMethodsTest() {
        // Authenticate as valid user.
        assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
        assumeTrue(connector.isAuthorized());

        List<AuthBackend> supportedBackends = assertDoesNotThrow(
            () -> connector.sys().getAuthBackends(),
            "Could not list supported auth backends"
        );

        assertEquals(3, supportedBackends.size());
        assertTrue(supportedBackends.containsAll(List.of(AuthBackend.TOKEN, AuthBackend.USERPASS, AuthBackend.APPROLE)));
    }

    /**
     * Test authentication using username and password.
     */
    @Test
    @DisplayName("Authenticate with UserPass")
    void authUserPassTest() {
        final String invalidUser = "foo";
        final String invalidPass = "bar";
        VaultConnectorException e = assertThrows(
            VaultConnectorException.class,
            () -> connector.authUserPass(invalidUser, invalidPass),
            "Logged in with invalid credentials"
        );
        // Assert that the exception does not reveal credentials.
        assertFalse(stackTrace(e).contains(invalidUser));
        assertFalse(stackTrace(e).contains(invalidPass));

        AuthResponse res = assertDoesNotThrow(
            () -> connector.authUserPass(USER_VALID, PASS_VALID),
            "Login failed with valid credentials: Exception thrown"
        );
        assertNotNull(res.auth(), "Login failed with valid credentials: Response not available");
        assertTrue(connector.isAuthorized(), "Login failed with valid credentials: Connector not authorized");
    }

    /**
     * Test sealing and unsealing Vault.
     */
    @Test
    @DisplayName("Seal test")
    void sealTest() throws VaultConnectorException {
        SealResponse sealStatus = connector.sys().sealStatus();
        assumeFalse(sealStatus.sealed());

        // Unauthorized sealing should fail.
        assertThrows(VaultConnectorException.class, () -> connector.sys().seal(), "Unauthorized sealing succeeded");
        assertFalse(sealStatus.sealed(), "Vault sealed, although sealing failed");

        // Root user should be able to seal.
        authRoot();
        assumeTrue(connector.isAuthorized());
        assertDoesNotThrow(() -> connector.sys().seal(), "Sealing failed");
        sealStatus = connector.sys().sealStatus();
        assertTrue(sealStatus.sealed(), "Vault not sealed");
        sealStatus = connector.sys().unseal(KEY2);
        assertTrue(sealStatus.sealed(), "Vault unsealed with only 1 key");
        sealStatus = connector.sys().unseal(KEY3);
        assertFalse(sealStatus.sealed(), "Vault not unsealed");
    }

    /**
     * Test health status
     */
    @Test
    @DisplayName("Health test")
    void healthTest() {
        HealthResponse res = assertDoesNotThrow(() -> connector.sys().getHealth(), "Retrieving health status failed");
        assertNotNull(res, "Health response should be set");
        assertEquals(VAULT_VERSION, res.version(), "Unexpected version");
        assertTrue(res.initialized(), "Unexpected init status");
        assertFalse(res.sealed(), "Unexpected seal status");
        assertFalse(res.standby(), "Unexpected standby status");

        // No seal vault and verify correct status.
        authRoot();
        assertDoesNotThrow(() -> connector.sys().seal(), "Unexpected exception on sealing");
        SealResponse sealStatus = assertDoesNotThrow(() -> connector.sys().sealStatus());
        assumeTrue(sealStatus.sealed());
        connector.resetAuth();  // Should work unauthenticated
        res = assertDoesNotThrow(() -> connector.sys().getHealth(), "Retrieving health status failed when sealed");
        assertTrue(res.sealed(), "Unexpected seal status");
    }

    /**
     * Test closing the connector.
     */
    @Test
    @DisplayName("Connector close test")
    void closeTest() throws NoSuchFieldException, IllegalAccessException {
        authUser();
        assumeTrue(connector.isAuthorized());

        assertDoesNotThrow(connector::close, "Closing the connector failed");
        assertFalse(connector.isAuthorized(), "Not unauthorized after close()");

        // Verify that (private) token has indeed been removed.
        Field tokenField = HTTPVaultConnector.class.getDeclaredField("token");
        tokenField.setAccessible(true);
        assertNull(tokenField.get(connector), "Token not removed after close()");
    }
}
