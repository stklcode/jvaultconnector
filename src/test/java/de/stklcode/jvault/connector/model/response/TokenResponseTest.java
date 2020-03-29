/*
 * Copyright 2016-2019 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.model.response.embedded.TokenData;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit Test for {@link TokenResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
public class TokenResponseTest {
    private static final Integer TOKEN_CREATION_TIME = 1457533232;
    private static final Integer TOKEN_TTL = 2764800;
    private static final String TOKEN_DISPLAY_NAME = "token";
    private static final String TOKEN_META_KEY = "foo";
    private static final String TOKEN_META_VALUE = "bar";
    private static final Integer TOKEN_NUM_USES = 0;
    private static final Boolean TOKEN_ORPHAN = false;
    private static final String TOKEN_PATH = "auth/token/create";
    private static final String TOKEN_POLICY_1 = "default";
    private static final String TOKEN_POLICY_2 = "web";
    private static final Boolean RES_RENEWABLE = false;
    private static final Integer RES_TTL = 2591976;
    private static final Integer RES_LEASE_DURATION = 0;

    private static final String RES_JSON = "{\n" +
            "  \"lease_id\": \"\",\n" +
            "  \"renewable\": " + RES_RENEWABLE + ",\n" +
            "  \"lease_duration\": " + RES_LEASE_DURATION + ",\n" +
            "  \"data\": {\n" +
            "    \"creation_time\": " + TOKEN_CREATION_TIME + ",\n" +
            "    \"creation_ttl\": " + TOKEN_TTL + ",\n" +
            "    \"display_name\": \"" + TOKEN_DISPLAY_NAME + "\",\n" +
            "    \"meta\": {\n" +
            "      \"" + TOKEN_META_KEY + "\": \"" + TOKEN_META_VALUE + "\"\n" +
            "    },\n" +
            "    \"num_uses\": " + TOKEN_NUM_USES + ",\n" +
            "    \"orphan\": " + TOKEN_ORPHAN + ",\n" +
            "    \"path\": \"" + TOKEN_PATH + "\",\n" +
            "    \"policies\": [\n" +
            "      \"" + TOKEN_POLICY_1 + "\", \n" +
            "      \"" + TOKEN_POLICY_2 + "\"\n" +
            "    ],\n" +
            "    \"ttl\": " + RES_TTL + "\n" +
            "  },\n" +
            "  \"warnings\": null,\n" +
            "  \"auth\": null\n" +
            "}";

    private static final Map<String, Object> INVALID_TOKEN_DATA = new HashMap<>();

    static {
        INVALID_TOKEN_DATA.put("num_uses", "fourtytwo");
    }

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    public void getDataRoundtrip() {
        // Create empty Object.
        TokenResponse res = new TokenResponse();
        assertThat("Initial data should be empty", res.getData(), is(nullValue()));

        // Parsing invalid data map should fail.
        try {
            res.setData(INVALID_TOKEN_DATA);
            fail("Parsing invalid token data succeeded");
        } catch (Exception e) {
            assertThat(e, is(instanceOf(InvalidResponseException.class)));
        }
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    public void jsonRoundtrip() {
        try {
            TokenResponse res = new ObjectMapper().readValue(RES_JSON, TokenResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            assertThat("Incorrect lease duration", res.getLeaseDuration(), is(RES_LEASE_DURATION));
            assertThat("Incorrect renewable status", res.isRenewable(), is(RES_RENEWABLE));
            // Extract token data.
            TokenData data = res.getData();
            assertThat("Token data is NULL", data, is(notNullValue()));
            assertThat("Incorrect token creation time", data.getCreationTime(), is(TOKEN_CREATION_TIME));
            assertThat("Incorrect token creation TTL", data.getCreationTtl(), is(TOKEN_TTL));
            assertThat("Incorrect token display name", data.getName(), is(TOKEN_DISPLAY_NAME));
            assertThat("Incorrect token number of uses", data.getNumUses(), is(TOKEN_NUM_USES));
            assertThat("Incorrect token orphan flag", data.isOrphan(), is(TOKEN_ORPHAN));
            assertThat("Incorrect token path", data.getPath(), is(TOKEN_PATH));
            assertThat("Incorrect token metadata size", data.getMeta().entrySet(), hasSize(1));
            assertThat("Incorrect token metadata", data.getMeta().get(TOKEN_META_KEY), is(TOKEN_META_VALUE));
            assertThat("Incorrect number of token policies", data.getPolicies(), hasSize(2));
            assertThat("Incorrect token policies", data.getPolicies(), contains(TOKEN_POLICY_1, TOKEN_POLICY_2));
            assertThat("Incorrect response renewable flag", res.isRenewable(), is(RES_RENEWABLE));
            assertThat("Incorrect response TTL", data.getTtl(), is(RES_TTL));
            assertThat("Incorrect response lease duration", res.getLeaseDuration(), is(RES_LEASE_DURATION));
        } catch (IOException e) {
            fail("TokenResponse deserialization failed: " + e.getMessage());
        }
    }
}
