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
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
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
class AuthMethodsResponseTest {
    private static final String GH_PATH = "github/";
    private static final String GH_TYPE = "github";
    private static final String GH_DESCR = "GitHub auth";
    private static final String TK_PATH = "token/";
    private static final String TK_TYPE = "token";
    private static final String TK_DESCR = "token based credentials";
    private static final Integer TK_LEASE_TTL = 0;
    private static final Integer TK_MAX_LEASE_TTL = 0;

    private static final String RES_JSON = "{\n" +
            "  \"data\": {" +
            "    \"" + GH_PATH + "\": {\n" +
            "      \"type\": \"" + GH_TYPE + "\",\n" +
            "      \"description\": \"" + GH_DESCR + "\"\n" +
            "    },\n" +
            "    \"" + TK_PATH + "\": {\n" +
            "      \"config\": {\n" +
            "        \"default_lease_ttl\": " + TK_LEASE_TTL + ",\n" +
            "        \"max_lease_ttl\": " + TK_MAX_LEASE_TTL + "\n" +
            "      },\n" +
            "      \"description\": \"" + TK_DESCR + "\",\n" +
            "      \"type\": \"" + TK_TYPE + "\"\n" +
            "    }\n" +
            "  }\n" +
            "}";

    private static final Map<String, Object> INVALID_DATA = Map.of("dummy/", new Dummy());

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    void getDataRoundtrip() {
        // Create empty Object.
        AuthMethodsResponse res = new AuthMethodsResponse();
        assertEquals(Collections.emptyMap(), res.getSupportedMethods(), "Initial method map should be empty");

        // Parsing invalid data map should fail.
        assertThrows(
                InvalidResponseException.class,
                () -> res.setData(INVALID_DATA),
                "Parsing invalid data succeeded"
        );
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        AuthMethodsResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(RES_JSON, AuthMethodsResponse.class),
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

        // Verify first method.
        method = supported.get(TK_PATH);
        assertEquals(TK_TYPE, method.getRawType(), "Incorrect raw type for Token");
        assertEquals(AuthBackend.TOKEN, method.getType(), "Incorrect parsed type for Token");
        assertEquals(TK_DESCR, method.getDescription(), "Incorrect description for Token");
        assertNotNull(method.getConfig(), "Missing config for Token");
        assertEquals(2, method.getConfig().size(), "Unexpected config size for Token");
        assertEquals(TK_LEASE_TTL.toString(), method.getConfig().get("default_lease_ttl"), "Incorrect lease TTL config");
        assertEquals(TK_MAX_LEASE_TTL.toString(), method.getConfig().get("max_lease_ttl"), "Incorrect max lease TTL config");
    }

    @Test
    void testEqualsHashcode() {
        EqualsVerifier.simple().forClass(AuthMethodsResponse.class).verify();
    }

    private static class Dummy implements Serializable {
        private static final long serialVersionUID = 9075949348402246139L;
    }
}
