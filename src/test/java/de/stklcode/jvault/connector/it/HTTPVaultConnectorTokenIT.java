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

import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.Token;
import de.stklcode.jvault.connector.model.TokenRole;
import de.stklcode.jvault.connector.model.response.AuthResponse;
import de.stklcode.jvault.connector.model.response.TokenResponse;
import de.stklcode.jvault.connector.model.response.TokenRoleResponse;
import org.junit.jupiter.api.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for HTTP Vault connector Token module.
 */
@DisplayName("Token Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HTTPVaultConnectorTokenIT extends HTTPVaultConnectorITBase {
    /**
     * Test authentication using token.
     */
    @Test
    @Order(10)
    @DisplayName("Authenticate with token")
    void authTokenTest() {
        final String invalidToken = "52135869df23a5e64c5d33a9785af5edb456b8a4a235d1fe135e6fba1c35edf6";
        VaultConnectorException e = assertThrows(
            VaultConnectorException.class,
            () -> connector.authToken(invalidToken),
            "Logged in with invalid token"
        );
        // Assert that the exception does not reveal the token.
        assertFalse(stackTrace(e).contains(invalidToken));


        TokenResponse res = assertDoesNotThrow(
            () -> connector.authToken(TOKEN_ROOT),
            "Login failed with valid token"
        );
        assertNotNull(res, "Login failed with valid token");
        assertTrue(connector.isAuthorized(), "Login failed with valid token");
    }

    /**
     * Test token creation.
     */
    @Test
    @Order(20)
    @DisplayName("Create token")
    void createTokenTest() {
        authRoot();
        assumeTrue(connector.isAuthorized());

        // Create token.
        Token token = Token.builder()
            .withId("test-id")
            .withType(Token.Type.SERVICE)
            .withDisplayName("test name")
            .build();

        // Create token.
        AuthResponse res = assertDoesNotThrow(() -> connector.token().create(token), "Token creation failed");
        assertNotNull(res, "No result given");
        assertEquals("test-id", res.auth().clientToken(), "Invalid token ID returned");
        assertEquals(List.of("root"), res.auth().policies(), "Expected inherited root policy");
        assertEquals(List.of("root"), res.auth().tokenPolicies(), "Expected inherited root policy for token");
        assertEquals(Token.Type.SERVICE.value(), res.auth().tokenType(), "Unexpected token type");
        assertNull(res.auth().metadata(), "Metadata unexpected");
        assertFalse(res.auth().renewable(), "Root token should not be renewable");
        assertFalse(res.auth().orphan(), "Root token should not be orphan");

        // Starting with Vault 1.0 a warning "custom ID uses weaker SHA1..." is given.
        // Starting with Vault 1.11 a second warning "Endpoint ignored unrecognized parameters" is given.
        assertFalse(res.warnings().isEmpty(), "Token creation did not return expected warning");

        // Create token with attributes.
        Token token2 = Token.builder()
            .withId("test-id2")
            .withDisplayName("test name 2")
            .withPolicies(Collections.singletonList("testpolicy"))
            .withoutDefaultPolicy()
            .withMeta("foo", "bar")
            .build();
        res = assertDoesNotThrow(() -> connector.token().create(token2), "Token creation failed");
        assertEquals("test-id2", res.auth().clientToken(), "Invalid token ID returned");
        assertEquals(List.of("testpolicy"), res.auth().policies(), "Invalid policies returned");
        assertNotNull(res.auth().metadata(), "Metadata not given");
        assertEquals("bar", res.auth().metadata().get("foo"), "Metadata not correct");
        assertTrue(res.auth().renewable(), "Token should be renewable");

        // Overwrite token should fail as of Vault 0.8.0.
        Token token3 = Token.builder()
            .withId("test-id2")
            .withDisplayName("test name 3")
            .withPolicies(Arrays.asList("pol1", "pol2"))
            .withDefaultPolicy()
            .withMeta("test", "success")
            .withMeta("key", "value")
            .withTtl(1234L)
            .build();
        InvalidResponseException e = assertThrows(
            InvalidResponseException.class,
            () -> connector.token().create(token3),
            "Overwriting token should fail as of Vault 0.8.0"
        );
        assertEquals(400, e.getStatusCode());
        // Assert that the exception does not reveal token ID.
        assertFalse(stackTrace(e).contains(token3.id()));

        // Create token with batch type.
        Token token4 = Token.builder()
            .withDisplayName("test name 3")
            .withPolicy("batchpolicy")
            .withoutDefaultPolicy()
            .withType(Token.Type.BATCH)
            .build();
        res = assertDoesNotThrow(() -> connector.token().create(token4, false), "Token creation failed");
        assertTrue(
            // Expecting batch token. "hvb." Prefix as of Vault 1.10, "b." before.
            res.auth().clientToken().startsWith("b.") || res.auth().clientToken().startsWith("hvb."),
            "Unexpected token prefix"
        );
        assertEquals(1, res.auth().policies().size(), "Invalid number of policies returned");
        assertTrue(res.auth().policies().contains("batchpolicy"), "Custom policy policy not set");
        assertFalse(res.auth().renewable(), "Token should not be renewable");
        assertFalse(res.auth().orphan(), "Token should not be orphan");
        assertEquals(Token.Type.BATCH.value(), res.auth().tokenType(), "Specified token Type not set");
    }

    /**
     * Test token lookup.
     */
    @Test
    @Order(30)
    @DisplayName("Lookup token")
    void lookupTokenTest() {
        authRoot();
        assumeTrue(connector.isAuthorized());

        // Create token with attributes.
        Token token = Token.builder()
            .withId("my-token")
            .withType(Token.Type.SERVICE)
            .build();
        assertDoesNotThrow(() -> connector.token().create(token), "Token creation failed");

        authRoot();
        assumeTrue(connector.isAuthorized());

        TokenResponse res = assertDoesNotThrow(() -> connector.token().lookup("my-token"), "Token creation failed");
        assertEquals(token.id(), res.data().id(), "Unexpected token ID");
        assertEquals(1, res.data().policies().size(), "Unexpected number of policies");
        assertTrue(res.data().policies().contains("root"), "Unexpected policy");
        assertEquals(token.type(), res.data().type(), "Unexpected token type");
        assertNotNull(res.data().issueTime(), "Issue time expected to be filled");
    }

    /**
     * Test token role handling.
     */
    @Test
    @Order(40)
    @DisplayName("Token roles")
    void tokenRolesTest() {
        authRoot();
        assumeTrue(connector.isAuthorized());

        // Create token role.
        final String roleName = "test-role";
        final TokenRole role = TokenRole.builder().build();

        boolean creationRes = assertDoesNotThrow(
            () -> connector.token().createOrUpdateRole(roleName, role),
            "Token role creation failed"
        );
        assertTrue(creationRes, "Token role creation failed");

        // Read the role.
        TokenRoleResponse res = assertDoesNotThrow(
            () -> connector.token().readRole(roleName),
            "Reading token role failed"
        );
        assertNotNull(res, "Token role response must not be null");
        assertNotNull(res.data(), "Token role must not be null");
        assertEquals(roleName, res.data().name(), "Token role name not as expected");
        assertTrue(res.data().renewable(), "Token role expected to be renewable by default");
        assertFalse(res.data().orphan(), "Token role not expected to be orphan by default");
        assertEquals(Token.Type.DEFAULT_SERVICE.value(), res.data().tokenType(), "Unexpected default token type");

        // Update the role, i.e. change some attributes.
        final TokenRole role2 = TokenRole.builder()
            .forName(roleName)
            .withPathSuffix("suffix")
            .orphan(true)
            .renewable(false)
            .withTokenNumUses(42)
            .build();

        creationRes = assertDoesNotThrow(
            () -> connector.token().createOrUpdateRole(role2),
            "Token role update failed"
        );
        assertTrue(creationRes, "Token role update failed");

        res = assertDoesNotThrow(() -> connector.token().readRole(roleName), "Reading token role failed");
        assertNotNull(res, "Token role response must not be null");
        assertNotNull(res.data(), "Token role must not be null");
        assertEquals(roleName, res.data().name(), "Token role name not as expected");
        assertFalse(res.data().renewable(), "Token role not expected to be renewable  after update");
        assertTrue(res.data().orphan(), "Token role expected to be orphan  after update");
        assertEquals(42, res.data().tokenNumUses(), "Unexpected number of token uses after update");

        // List roles.
        List<String> listRes = assertDoesNotThrow(() -> connector.token().listRoles(), "Listing token roles failed");
        assertNotNull(listRes, "Token role list must not be null");
        assertEquals(List.of(roleName), listRes, "Unexpected token role list");

        // Delete the role.
        creationRes = assertDoesNotThrow(() -> connector.token().deleteRole(roleName), "Token role deletion failed");
        assertTrue(creationRes, "Token role deletion failed");
        assertThrows(InvalidResponseException.class, () -> connector.token().readRole(roleName), "Reading nonexistent token role should fail");
        assertThrows(InvalidResponseException.class, () -> connector.token().listRoles(), "Listing nonexistent token roles should fail");
    }
}
