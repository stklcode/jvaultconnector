/*
 * Copyright 2016-2023 Stefan Kalscheuer
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

import com.fasterxml.jackson.core.JsonProcessingException;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import de.stklcode.jvault.connector.model.response.embedded.TokenData;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link TokenResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class TokenResponseTest extends AbstractModelTest<TokenResponse> {
    private static final Integer TOKEN_CREATION_TIME = 1457533232;
    private static final Integer TOKEN_TTL = 2764800;
    private static final Integer TOKEN_EXPLICIT_MAX_TTL = 0;
    private static final String TOKEN_DISPLAY_NAME = "token";
    private static final String TOKEN_META_KEY = "foo";
    private static final String TOKEN_META_VALUE = "bar";
    private static final Integer TOKEN_NUM_USES = 0;
    private static final Boolean TOKEN_ORPHAN = false;
    private static final Boolean TOKEN_RENEWABLE = true;
    private static final String TOKEN_PATH = "auth/token/create";
    private static final String TOKEN_POLICY_1 = "default";
    private static final String TOKEN_POLICY_2 = "web";
    private static final Boolean RES_RENEWABLE = false;
    private static final Integer RES_TTL = 2591976;
    private static final Integer RES_LEASE_DURATION = 0;
    private static final String TOKEN_ACCESSOR = "VKvzT2fKHFsZFUus9LyoXCvu";
    private static final String TOKEN_ENTITY_ID = "7d2e3179-f69b-450c-7179-ac8ee8bd8ca9";
    private static final String TOKEN_EXPIRE_TIME = "2018-05-19T11:35:54.466476215-04:00";
    private static final String TOKEN_ID = "my-token";
    private static final String TOKEN_ISSUE_TIME = "2018-04-17T11:35:54.466476078-04:00";
    private static final String TOKEN_TYPE = "service";

    private static final String RES_JSON = "{\n" +
            "  \"lease_id\": \"\",\n" +
            "  \"renewable\": " + RES_RENEWABLE + ",\n" +
            "  \"lease_duration\": " + RES_LEASE_DURATION + ",\n" +
            "  \"data\": {\n" +
            "    \"accessor\": \"" + TOKEN_ACCESSOR + "\",\n" +
            "    \"creation_time\": " + TOKEN_CREATION_TIME + ",\n" +
            "    \"creation_ttl\": " + TOKEN_TTL + ",\n" +
            "    \"display_name\": \"" + TOKEN_DISPLAY_NAME + "\",\n" +
            "    \"entity_id\": \"" + TOKEN_ENTITY_ID + "\",\n" +
            "    \"expire_time\": \"" + TOKEN_EXPIRE_TIME + "\",\n" +
            "    \"explicit_max_ttl\": \"" + TOKEN_EXPLICIT_MAX_TTL + "\",\n" +
            "    \"id\": \"" + TOKEN_ID + "\",\n" +
            "    \"issue_time\": \"" + TOKEN_ISSUE_TIME + "\",\n" +
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
            "    \"renewable\": " + TOKEN_RENEWABLE + ",\n" +
            "    \"ttl\": " + RES_TTL + ",\n" +
            "    \"type\": \"" + TOKEN_TYPE + "\"\n" +
            "  },\n" +
            "  \"warnings\": null,\n" +
            "  \"auth\": null\n" +
            "}";

    TokenResponseTest() {
        super(TokenResponse.class);
    }

    @Override
    protected TokenResponse createFull() {
        try {
            return objectMapper.readValue(RES_JSON, TokenResponse.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    void getDataRoundtrip() {
        // Create empty Object.
        TokenResponse res = new TokenResponse();
        assertNull(res.getData(), "Initial data should be empty");
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        TokenResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(RES_JSON, TokenResponse.class),
                "TokenResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(RES_LEASE_DURATION, res.getLeaseDuration(), "Incorrect lease duration");
        assertEquals(RES_RENEWABLE, res.isRenewable(), "Incorrect response renewable flag");
        assertEquals(RES_LEASE_DURATION, res.getLeaseDuration(), "Incorrect response lease duration");
        // Extract token data.
        TokenData data = res.getData();
        assertNotNull(data, "Token data is NULL");
        assertEquals(TOKEN_ACCESSOR, data.getAccessor(), "Incorrect token accessor");
        assertEquals(TOKEN_CREATION_TIME, data.getCreationTime(), "Incorrect token creation time");
        assertEquals(TOKEN_TTL, data.getCreationTtl(), "Incorrect token creation TTL");
        assertEquals(TOKEN_DISPLAY_NAME, data.getName(), "Incorrect token display name");
        assertEquals(TOKEN_ENTITY_ID, data.getEntityId(), "Incorrect token entity ID");
        assertEquals(TOKEN_EXPIRE_TIME, data.getExpireTimeString(), "Incorrect token expire time");
        assertEquals(ZonedDateTime.parse(TOKEN_EXPIRE_TIME), data.getExpireTime(), "Incorrect parsed token expire time");
        assertEquals(TOKEN_EXPLICIT_MAX_TTL, data.getExplicitMaxTtl(), "Incorrect token explicit max TTL");
        assertEquals(TOKEN_ID, data.getId(), "Incorrect token ID");
        assertEquals(TOKEN_ISSUE_TIME, data.getIssueTimeString(), "Incorrect token issue time");
        assertEquals(ZonedDateTime.parse(TOKEN_ISSUE_TIME), data.getIssueTime(), "Incorrect parsed token issue time");
        assertEquals(Map.of(TOKEN_META_KEY, TOKEN_META_VALUE), data.getMeta(), "Incorrect token metadata");
        assertEquals(TOKEN_NUM_USES, data.getNumUses(), "Incorrect token number of uses");
        assertEquals(TOKEN_ORPHAN, data.isOrphan(), "Incorrect token orphan flag");
        assertEquals(TOKEN_PATH, data.getPath(), "Incorrect token path");
        assertEquals(2, data.getPolicies().size(), "Incorrect number of token policies");
        assertTrue(data.getPolicies().containsAll(List.of(TOKEN_POLICY_1, TOKEN_POLICY_2)), "Incorrect token policies");
        assertEquals(TOKEN_RENEWABLE, data.isRenewable(), "Incorrect token renewable flag");
        assertEquals(RES_TTL, data.getTtl(), "Incorrect token TTL");
        assertEquals(TOKEN_TYPE, data.getType(), "Incorrect token type");
    }
}
