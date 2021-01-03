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

package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit Test for {@link AuthResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
public class AuthResponseTest {
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
    public void getDataRoundtrip() {
        // Create empty Object.
        AuthResponse res = new AuthResponse();
        assertThat("Initial data should be empty", res.getData(), is(nullValue()));

        // Parsing invalid auth data map should fail.
        try {
            res.setAuth(INVALID_AUTH_DATA);
            fail("Parsing invalid auth data succeeded");
        } catch (Exception e) {
            assertThat(e, is(instanceOf(InvalidResponseException.class)));
        }

        // Data method should be agnostic.
        res.setData(INVALID_AUTH_DATA);
        assertThat("Data not passed through", res.getData(), is(INVALID_AUTH_DATA));
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    public void jsonRoundtrip() {
        try {
            AuthResponse res = new ObjectMapper().readValue(RES_JSON, AuthResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            // Extract auth data.
            AuthData data = res.getAuth();
            assertThat("Auth data is NULL", data, is(notNullValue()));
            assertThat("Incorrect auth accessor", data.getAccessor(), is(AUTH_ACCESSOR));
            assertThat("Incorrect auth client token", data.getClientToken(), is(AUTH_CLIENT_TOKEN));
            assertThat("Incorrect auth lease duration", data.getLeaseDuration(), is(AUTH_LEASE_DURATION));
            assertThat("Incorrect auth renewable flag", data.isRenewable(), is(AUTH_RENEWABLE));
            assertThat("Incorrect auth orphan flag", data.isOrphan(), is(AUTH_ORPHAN));
            assertThat("Incorrect auth token type", data.getTokenType(), is(AUTH_TOKEN_TYPE));
            assertThat("Incorrect auth entity id", data.getEntityId(), is(AUTH_ENTITY_ID));
            assertThat("Incorrect number of policies", data.getPolicies(), hasSize(2));
            assertThat("Incorrect auth policies", data.getPolicies(), containsInRelativeOrder(AUTH_POLICY_1, AUTH_POLICY_2));
            assertThat("Incorrect number of token policies", data.getTokenPolicies(), hasSize(2));
            assertThat("Incorrect token policies", data.getTokenPolicies(), containsInRelativeOrder(AUTH_POLICY_2, AUTH_POLICY_1));
            assertThat("Incorrect auth metadata size", data.getMetadata().entrySet(), hasSize(1));
            assertThat("Incorrect auth metadata", data.getMetadata().get(AUTH_META_KEY), is(AUTH_META_VALUE));

        } catch (IOException e) {
            fail("AuthResponse deserialization failed: " + e.getMessage());
        }
    }
}
