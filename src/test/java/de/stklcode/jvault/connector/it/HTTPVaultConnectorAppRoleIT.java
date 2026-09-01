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

import de.stklcode.jvault.connector.exception.AuthorizationRequiredException;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.AppRole;
import de.stklcode.jvault.connector.model.response.AppRoleResponse;
import de.stklcode.jvault.connector.model.response.AppRoleSecretResponse;
import org.junit.jupiter.api.*;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for HTTP Vault connector AppRole module.
 */
@DisplayName("AppRole Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HTTPVaultConnectorAppRoleIT extends HTTPVaultConnectorITBase {
    private static final String ROLE_NAME = "testrole1";                          // Role with secret ID.
    private static final String ROLE = "06eae026-7d4b-e4f8-0ec4-4107eb483975";
    private static final String SECRET = "20320293-c1c1-3b22-20f8-e5c960da0b5b";
    private static final String SECRET_ACCESSOR = "3b45a7c2-8d1c-abcf-c732-ecf6db16a8e1";
    private static final String ROLE2_NAME = "testrole2";                         // Role with CIDR subnet.
    private static final String ROLE2 = "40224890-1563-5193-be4b-0b4f9f573b7f";

    /**
     * App-ID authentication roundtrip.
     */
    @Test
    @Order(10)
    @DisplayName("Authenticate with AppRole")
    void authAppRole() {
        Assumptions.assumeFalse(connector.isAuthorized());

        // Authenticate with correct credentials.
        Assertions.assertDoesNotThrow(
            () -> connector.authAppRole(ROLE, SECRET),
            "Failed to authenticate using AppRole"
        );
        Assertions.assertTrue(connector.isAuthorized(), "Authorization flag not set after AppRole login");

        // Authenticate with valid secret ID against unknown role.
        final String invalidRole = "foo";
        InvalidResponseException e = assertThrows(
            InvalidResponseException.class,
            () -> connector.authAppRole(invalidRole, SECRET),
            "Successfully logged in with unknown role"
        );
        // Assert that the exception does not reveal role ID or secret.
        assertFalse(stackTrace(e).contains(invalidRole));
        assertFalse(stackTrace(e).contains(SECRET));

        // Authenticate without wrong secret ID.
        final String invalidSecret = "foo";
        e = assertThrows(
            InvalidResponseException.class,
            () -> connector.authAppRole(ROLE, "foo"),
            "Successfully logged in without secret ID"
        );
        // Assert that the exception does not reveal role ID or secret.
        assertFalse(stackTrace(e).contains(ROLE));
        assertFalse(stackTrace(e).contains(invalidSecret));

        // Authenticate without secret ID.
        e = assertThrows(
            InvalidResponseException.class,
            () -> connector.authAppRole(ROLE),
            "Successfully logged in without secret ID"
        );
        // Assert that the exception does not reveal role ID.
        assertFalse(stackTrace(e).contains(ROLE));

        // Authenticate with secret ID on role with CIDR whitelist.
        Assertions.assertDoesNotThrow(
            () -> connector.authAppRole(ROLE2, SECRET),
            "Failed to log in without secret ID"
        );
        Assertions.assertTrue(connector.isAuthorized(), "Authorization flag not set after AppRole login");
    }

    /**
     * Test listing of AppRole roles and secrets.
     */
    @Test
    @Order(20)
    @DisplayName("List AppRoles")
    void listAppRoleTest() {
        // Try unauthorized access first.
        Assumptions.assumeFalse(connector.isAuthorized());

        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().listRoles());

        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().listSecrets(""));

        // Authorize.
        authRoot();
        Assumptions.assumeTrue(connector.isAuthorized());

        // Verify pre-existing rules.
        List<String> res = Assertions.assertDoesNotThrow(() -> connector.appRole().listRoles(), "Role listing failed");
        assertEquals(2, res.size(), "Unexpected number of AppRoles");
        assertTrue(res.containsAll(List.of(ROLE_NAME, ROLE2_NAME)), "Pre-configured roles not listed");

        // Check secret IDs.
        res = Assertions.assertDoesNotThrow(() -> connector.appRole().listSecrets(ROLE_NAME), "AppRole secret listing failed");
        assertEquals(List.of(SECRET_ACCESSOR), res, "Pre-configured AppRole secret not listed");
    }

    /**
     * Test creation of a new AppRole.
     */
    @Test
    @Order(30)
    @DisplayName("Create AppRole")
    void createAppRoleTest() {
        // Try unauthorized access first.
        Assumptions.assumeFalse(connector.isAuthorized());
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().create(AppRole.builder(null).build()));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().lookup(""));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().delete(""));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().getRoleID(""));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().setRoleID("", ""));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().createSecret("", ""));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().lookupSecret("", ""));
        assertThrows(AuthorizationRequiredException.class, () -> connector.appRole().destroySecret("", ""));

        // Authorize.
        authRoot();
        Assumptions.assumeTrue(connector.isAuthorized());

        String roleName = "TestRole";

        // Create role model.
        AppRole role = AppRole.builder(roleName).build();

        // Create role.
        boolean createRes = Assertions.assertDoesNotThrow(() -> connector.appRole().create(role), "Role creation failed");
        assertTrue(createRes, "Role creation failed");

        // Lookup role.
        AppRoleResponse res = Assertions.assertDoesNotThrow(() -> connector.appRole().lookup(roleName), "Role lookup failed");
        assertNotNull(res.role(), "Role lookup returned no role");

        // Lookup role ID.
        String roleID = Assertions.assertDoesNotThrow(() -> connector.appRole().getRoleID(roleName), "Role ID lookup failed");
        assertNotEquals("", roleID, "Role ID lookup returned empty ID");

        // Set custom role ID.
        String roleID2 = "custom-role-id";
        Assertions.assertDoesNotThrow(() -> connector.appRole().setRoleID(roleName, roleID2), "Setting custom role ID failed");

        // Verify role ID.
        String res2 = Assertions.assertDoesNotThrow(() -> connector.appRole().getRoleID(roleName), "Role ID lookup failed");
        assertEquals(roleID2, res2, "Role ID lookup returned wrong ID");

        // Update role model with custom flags.
        AppRole role2 = AppRole.builder(roleName)
            .withTokenPeriod(321)
            .build();

        // Create role.
        boolean res3 = Assertions.assertDoesNotThrow(() -> connector.appRole().create(role2), "Role creation failed");
        assertTrue(res3, "No result given");

        // Lookup updated role.
        res = Assertions.assertDoesNotThrow(() -> connector.appRole().lookup(roleName), "Role lookup failed");
        assertNotNull(res.role(), "Role lookup returned no role");
        assertEquals(321, res.role().tokenPeriod(), "Token period not set for role");

        // Create role by name.
        String roleName2 = "RoleByName";
        Assertions.assertDoesNotThrow(() -> connector.appRole().create(roleName2), "Creation of role by name failed");
        res = Assertions.assertDoesNotThrow(() -> connector.appRole().lookup(roleName2), "Creation of role by name failed");
        assertNotNull(res.role(), "Role lookuo returned not value");

        // Create role by name with custom ID.
        String roleName3 = "RoleByName";
        String roleID3 = "RolyByNameID";
        Assertions.assertDoesNotThrow(() -> connector.appRole().create(roleName3, roleID3), "Creation of role by name failed");
        res = Assertions.assertDoesNotThrow(() -> connector.appRole().lookup(roleName3), "Creation of role by name failed");
        assertNotNull(res.role(), "Role lookuo returned not value");

        res2 = Assertions.assertDoesNotThrow(() -> connector.appRole().getRoleID(roleName3), "Creation of role by name failed");
        assertEquals(roleID3, res2, "Role lookuo returned wrong ID");

        // Create role by name with policies.
        Assertions.assertDoesNotThrow(
            () -> connector.appRole().create(roleName3, Collections.singletonList("testpolicy")),
            "Creation of role by name failed"
        );
        res = Assertions.assertDoesNotThrow(() -> connector.appRole().lookup(roleName3), "Creation of role by name failed");
        // Note: As of Vault 0.8.3 default policy is not added automatically, so this test should return 1, not 2.
        assertEquals(List.of("testpolicy"), res.role().tokenPolicies(), "Role lookup returned unexpected policies");

        // Delete role.
        Assertions.assertDoesNotThrow(() -> connector.appRole().delete(roleName3), "Deletion of role failed");
        assertThrows(
            InvalidResponseException.class,
            () -> connector.appRole().lookup(roleName3),
            "Deleted role could be looked up"
        );
    }

    /**
     * Test creation of AppRole secrets.
     */
    @Test
    @Order(40)
    @DisplayName("Create AppRole secrets")
    void createAppRoleSecretTest() {
        authRoot();
        Assumptions.assumeTrue(connector.isAuthorized());

        // Create default (random) secret for existing role.
        AppRoleSecretResponse res = Assertions.assertDoesNotThrow(
            () -> connector.appRole().createSecret(ROLE_NAME),
            "AppRole secret creation failed"
        );
        assertNotNull(res.secret(), "No secret returned");

        // Create secret with custom ID.
        String secretID = "customSecretId";
        res = Assertions.assertDoesNotThrow(
            () -> connector.appRole().createSecret(ROLE_NAME, secretID),
            "AppRole secret creation failed"
        );
        assertEquals(secretID, res.secret().id(), "Unexpected secret ID returned");

        // Lookup secret.
        res = Assertions.assertDoesNotThrow(
            () -> connector.appRole().lookupSecret(ROLE_NAME, secretID),
            "AppRole secret lookup failed"
        );
        assertNotNull(res.secret(), "No secret information returned");

        // Destroy secret.
        Assertions.assertDoesNotThrow(
            () -> connector.appRole().destroySecret(ROLE_NAME, secretID),
            "AppRole secret destruction failed"
        );
        assertThrows(
            InvalidResponseException.class,
            () -> connector.appRole().lookupSecret(ROLE_NAME, secretID),
            "Destroyed AppRole secret successfully read"
        );
    }
}
