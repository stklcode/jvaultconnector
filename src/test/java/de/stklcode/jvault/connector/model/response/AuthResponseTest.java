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
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link AuthResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class AuthResponseTest {
    private static final String AUTH_ACCESSOR = "2c84f488-2133-4ced-87b0-570f93a76830";
    private static final String AUTH_CLIENT_TOKEN = "ABCD";
    private static final String AUTH_POLICY_1 = "web";
    private static final String AUTH_POLICY_2 = "stage";
    private static final String AUTH_META_KEY = "user";
    private static final String AUTH_META_VALUE = "armon";
    private static final Integer AUTH_LEASE_DURATION = 3600;
    private static final Boolean AUTH_RENEWABLE = true;
    private static final String AUTH_ENTITY_ID = "";
    private static final String AUTH_TOKEN_TYPE = "service";
    private static final Boolean AUTH_ORPHAN = false;

    private static final String RES_JSON = "{\n" +
            "  \"auth\": {\n" +
            "    \"accessor\": \"" + AUTH_ACCESSOR + "\",\n" +
            "    \"client_token\": \"" + AUTH_CLIENT_TOKEN + "\",\n" +
            "    \"policies\": [\n" +
            "      \"" + AUTH_POLICY_1 + "\", \n" +
            "      \"" + AUTH_POLICY_2 + "\"\n" +
            "    ],\n" +
            "    \"token_policies\": [\n" +
            "      \"" + AUTH_POLICY_2 + "\",\n" +
            "      \"" + AUTH_POLICY_1 + "\" \n" +
            "    ],\n" +
            "    \"metadata\": {\n" +
            "      \"" + AUTH_META_KEY + "\": \"" + AUTH_META_VALUE + "\"\n" +
            "    },\n" +
            "    \"lease_duration\": " + AUTH_LEASE_DURATION + ",\n" +
            "    \"renewable\": " + AUTH_RENEWABLE + ",\n" +
            "    \"entity_id\": \"" + AUTH_ENTITY_ID + "\",\n" +
            "    \"token_type\": \"" + AUTH_TOKEN_TYPE + "\",\n" +
            "    \"orphan\": " + AUTH_ORPHAN + "\n" +
            "  }\n" +
            "}";

    private static final Map<String, Object> INVALID_AUTH_DATA = new HashMap<>();

    static {
        INVALID_AUTH_DATA.put("policies", "fancy-policy");
    }

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    void getDataRoundtrip() {
        // Create empty Object.
        AuthResponse res = new AuthResponse();
        assertNull(res.getData(), "Initial data should be empty");

        // Parsing invalid auth data map should fail.
        assertThrows(
                InvalidResponseException.class,
                () -> res.setAuth(INVALID_AUTH_DATA),
                "Parsing invalid auth data succeeded"
        );

        // Data method should be agnostic.
        res.setData(INVALID_AUTH_DATA);
        assertEquals(INVALID_AUTH_DATA, res.getData(), "Data not passed through");
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        AuthResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(RES_JSON, AuthResponse.class),
                "AuthResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        // Extract auth data.
        AuthData data = res.getAuth();
        assertNotNull(data, "Auth data is NULL");
        assertEquals(AUTH_ACCESSOR, data.getAccessor(), "Incorrect auth accessor");
        assertEquals(AUTH_CLIENT_TOKEN, data.getClientToken(), "Incorrect auth client token");
        assertEquals(AUTH_LEASE_DURATION, data.getLeaseDuration(), "Incorrect auth lease duration");
        assertEquals(AUTH_RENEWABLE, data.isRenewable(), "Incorrect auth renewable flag");
        assertEquals(AUTH_ORPHAN, data.isOrphan(), "Incorrect auth orphan flag");
        assertEquals(AUTH_TOKEN_TYPE, data.getTokenType(), "Incorrect auth token type");
        assertEquals(AUTH_ENTITY_ID, data.getEntityId(), "Incorrect auth entity id");
        assertEquals(2, data.getPolicies().size(), "Incorrect number of policies");
        assertTrue(data.getPolicies().containsAll(Set.of(AUTH_POLICY_1, AUTH_POLICY_2)));
        assertEquals(2, data.getTokenPolicies().size(), "Incorrect number of token policies");
        assertTrue(data.getTokenPolicies().containsAll(Set.of(AUTH_POLICY_2, AUTH_POLICY_1)), "Incorrect token policies");
        assertEquals(Map.of(AUTH_META_KEY, AUTH_META_VALUE), data.getMetadata(), "Incorrect auth metadata");
    }
}
