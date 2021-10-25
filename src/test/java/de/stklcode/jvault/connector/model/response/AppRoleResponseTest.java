/*
 * Copyright 2016-2022 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.model.AppRole;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link AppRoleResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class AppRoleResponseTest {
    private static final Integer ROLE_TOKEN_TTL = 1200;
    private static final Integer ROLE_TOKEN_MAX_TTL = 1800;
    private static final Integer ROLE_SECRET_TTL = 600;
    private static final Integer ROLE_SECRET_NUM_USES = 40;
    private static final String ROLE_POLICY = "default";
    private static final Integer ROLE_PERIOD = 0;
    private static final Boolean ROLE_BIND_SECRET = true;

    private static final String RES_JSON = "{\n" +
            "  \"auth\": null,\n" +
            "  \"warnings\": null,\n" +
            "  \"wrap_info\": null,\n" +
            "  \"data\": {\n" +
            "    \"token_ttl\": " + ROLE_TOKEN_TTL + ",\n" +
            "    \"token_max_ttl\": " + ROLE_TOKEN_MAX_TTL + ",\n" +
            "    \"secret_id_ttl\": " + ROLE_SECRET_TTL + ",\n" +
            "    \"secret_id_num_uses\": " + ROLE_SECRET_NUM_USES + ",\n" +
            "    \"token_policies\": [\n" +
            "      \"" + ROLE_POLICY + "\"\n" +
            "    ],\n" +
            "    \"token_period\": " + ROLE_PERIOD + ",\n" +
            "    \"bind_secret_id\": " + ROLE_BIND_SECRET + ",\n" +
            "    \"bound_cidr_list\": \"\"\n" +
            "  },\n" +
            "  \"lease_duration\": 0,\n" +
            "  \"renewable\": false,\n" +
            "  \"lease_id\": \"\"\n" +
            "}";

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    void getDataRoundtrip() {
        // Create empty Object.
        AppRoleResponse res = new AppRoleResponse();
        assertNull(res.getRole(), "Initial data should be empty");
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        AppRoleResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(RES_JSON, AppRoleResponse.class),
                "AuthResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        // Extract role data.
        AppRole role = res.getRole();
        assertNotNull(role, "Role data is NULL");
        assertEquals(ROLE_TOKEN_TTL, role.getTokenTtl(), "Incorrect token TTL");
        assertEquals(ROLE_TOKEN_MAX_TTL, role.getTokenMaxTtl(), "Incorrect token max TTL");
        assertEquals(ROLE_SECRET_TTL, role.getSecretIdTtl(), "Incorrect secret ID TTL");
        assertEquals(ROLE_SECRET_NUM_USES, role.getSecretIdNumUses(), "Incorrect secret ID umber of uses");
        assertEquals(List.of(ROLE_POLICY), role.getTokenPolicies(), "Incorrect policies");
        assertEquals(ROLE_PERIOD, role.getTokenPeriod(), "Incorrect role period");
        assertEquals(ROLE_BIND_SECRET, role.getBindSecretId(), "Incorrect role bind secret ID flag");
        assertNull(role.getTokenBoundCidrs(), "Incorrect bound CIDR list");
        assertEquals("", role.getTokenBoundCidrsString(), "Incorrect bound CIDR list string");
    }

    @Test
    void testEqualsHashcode() {
        EqualsVerifier.simple().forClass(AppRoleResponse.class).verify();
    }
}
