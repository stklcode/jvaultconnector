/*
 * Copyright 2016-2025 Stefan Kalscheuer
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

import de.stklcode.jvault.connector.model.AbstractModelTest;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link AuthMethodsResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class AuthMethodsResponseTest extends AbstractModelTest<AuthMethodsResponse> {
    private static final String GH_PATH = "github/";
    private static final String GH_TYPE = "github";
    private static final String GH_UUID = "4b42d1a4-0a0d-3c88-ae90-997e0c8b41be";
    private static final String GH_ACCESSOR = "auth_github_badd7fd0";
    private static final String GH_DESCR = "GitHub auth";
    private static final String TK_PATH = "token/";
    private static final String TK_TYPE = "token";
    private static final String TK_UUID = "32ea9681-6bd6-6cec-eec3-d11260ba9741";
    private static final String TK_ACCESSOR = "auth_token_ac0dd95a";
    private static final String TK_DESCR = "token based credentials";
    private static final Long TK_LEASE_TTL = 0L;
    private static final Boolean TK_FORCE_NO_CACHE = false;
    private static final Long TK_MAX_LEASE_TTL = 0L;
    private static final String TK_TOKEN_TYPE = "default-service";
    private static final String TK_RUNNING_PLUGIN_VERSION = "v1.15.3+builtin.vault";

    private static final String RES_JSON = "{\n" +
            "  \"data\": {" +
            "    \"" + GH_PATH + "\": {\n" +
            "      \"uuid\": \"" + GH_UUID + "\",\n" +
            "      \"type\": \"" + GH_TYPE + "\",\n" +
            "      \"accessor\": \"" + GH_ACCESSOR + "\",\n" +
            "      \"description\": \"" + GH_DESCR + "\",\n" +
            "      \"external_entropy_access\": false,\n" +
            "      \"local\": false,\n" +
            "      \"seal_wrap\": false\n" +
            "    },\n" +
            "    \"" + TK_PATH + "\": {\n" +
            "      \"config\": {\n" +
            "        \"default_lease_ttl\": " + TK_LEASE_TTL + ",\n" +
            "        \"force_no_cache\": " + TK_FORCE_NO_CACHE + ",\n" +
            "        \"max_lease_ttl\": " + TK_MAX_LEASE_TTL + ",\n" +
            "        \"token_type\": \"" + TK_TOKEN_TYPE + "\"\n" +
            "      },\n" +
            "      \"description\": \"" + TK_DESCR + "\",\n" +
            "      \"options\": null,\n" +
            "      \"plugin_version\": \"\",\n" +
            "      \"running_plugin_version\": \"" + TK_RUNNING_PLUGIN_VERSION + "\",\n" +
            "      \"running_sha256\": \"\",\n" +
            "      \"type\": \"" + TK_TYPE + "\",\n" +
            "      \"uuid\": \"" + TK_UUID + "\",\n" +
            "      \"accessor\": \"" + TK_ACCESSOR + "\",\n" +
            "      \"external_entropy_access\": false,\n" +
            "      \"local\": true,\n" +
            "      \"seal_wrap\": false\n" +
            "    }\n" +
            "  }\n" +
            "}";

    AuthMethodsResponseTest() {
        super(AuthMethodsResponse.class);
    }

    @Override
    protected AuthMethodsResponse createFull() {
        return assertDoesNotThrow(
            () -> objectMapper.readValue(RES_JSON, AuthMethodsResponse.class),
            "Creation of full model instance failed"
        );
    }

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    void getDataRoundtrip() {
        // Create empty Object.
        AuthMethodsResponse res = new AuthMethodsResponse();
        assertEquals(Collections.emptyMap(), res.getSupportedMethods(), "Initial method map should be empty");
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        AuthMethodsResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(RES_JSON, AuthMethodsResponse.class),
                "AuthResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        // Extract auth data.
        Map<String, AuthMethod> supported = res.getSupportedMethods();
        assertNotNull(supported, "Auth data is NULL");
        assertEquals(2, supported.size(), "Incorrect number of supported methods");
        assertTrue(supported.keySet().containsAll(Set.of(GH_PATH, TK_PATH)), "Incorrect method paths");

        // Verify first method.
        AuthMethod method = supported.get(GH_PATH);
        assertEquals(GH_TYPE, method.getRawType(), "Incorrect raw type for GitHub");
        assertEquals(AuthBackend.GITHUB, method.getType(), "Incorrect parsed type for GitHub");
        assertEquals(GH_DESCR, method.getDescription(), "Incorrect description for GitHub");
        assertNull(method.getConfig(), "Unexpected config for GitHub");
        assertEquals(GH_UUID, method.getUuid(), "Unexpected UUID for GitHub");
        assertEquals(GH_ACCESSOR, method.getAccessor(), "Unexpected accessor for GitHub");
        assertFalse(method.isLocal(), "Unexpected local flag for GitHub");
        assertFalse(method.isExternalEntropyAccess(), "Unexpected external entropy flag for GitHub");
        assertFalse(method.isSealWrap(), "Unexpected seal wrap flag for GitHub");

        // Verify second method.
        method = supported.get(TK_PATH);
        assertEquals(TK_TYPE, method.getRawType(), "Incorrect raw type for Token");
        assertEquals(AuthBackend.TOKEN, method.getType(), "Incorrect parsed type for Token");
        assertEquals(TK_DESCR, method.getDescription(), "Incorrect description for Token");
        assertEquals(TK_UUID, method.getUuid(), "Unexpected UUID for Token");
        assertEquals(TK_ACCESSOR, method.getAccessor(), "Unexpected accessor for Token");
        assertTrue(method.isLocal(), "Unexpected local flag for Token");
        assertFalse(method.isExternalEntropyAccess(), "Unexpected external entropy flag for Token");
        assertFalse(method.isSealWrap(), "Unexpected seal wrap flag for GitHub");
        assertEquals("", method.getPluginVersion(), "Unexpected plugin version");
        assertEquals(TK_RUNNING_PLUGIN_VERSION, method.getRunningPluginVersion(), "Unexpected running plugin version");
        assertEquals("", method.getRunningSha256(), "Unexpected running SHA256");

        assertNotNull(method.getConfig(), "Missing config for Token");
        assertEquals(TK_LEASE_TTL, method.getConfig().getDefaultLeaseTtl(), "Unexpected default TTL");
        assertEquals(TK_MAX_LEASE_TTL, method.getConfig().getMaxLeaseTtl(), "Unexpected max TTL");
        assertEquals(TK_FORCE_NO_CACHE, method.getConfig().getForceNoCache(), "Unexpected force no cache flag");
        assertEquals(TK_TOKEN_TYPE, method.getConfig().getTokenType(), "Unexpected token type");

        assertNull(method.getOptions(), "Unexpected options");
    }
}
