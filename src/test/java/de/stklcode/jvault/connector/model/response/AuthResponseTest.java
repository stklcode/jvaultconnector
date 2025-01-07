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

import com.fasterxml.jackson.core.JsonProcessingException;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;
import de.stklcode.jvault.connector.model.response.embedded.MfaConstraintAny;
import de.stklcode.jvault.connector.model.response.embedded.MfaMethodId;
import de.stklcode.jvault.connector.model.response.embedded.MfaRequirement;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link AuthResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class AuthResponseTest extends AbstractModelTest<AuthResponse> {
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
    private static final Integer AUTH_NUM_USES = 42;
    private static final String MFA_REQUEST_ID = "d0c9eec7-6921-8cc0-be62-202b289ef163";
    private static final String MFA_KEY = "enforcementConfigUserpass";
    private static final String MFA_METHOD_TYPE = "totp";
    private static final String MFA_METHOD_ID = "820997b3-110e-c251-7e8b-ff4aa428a6e1";
    private static final Boolean MFA_METHOD_USES_PASSCODE = true;
    private static final String MFA_METHOD_NAME = "sample_mfa_method_name";

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
        "    \"orphan\": " + AUTH_ORPHAN + ",\n" +
        "    \"num_uses\": " + AUTH_NUM_USES + ",\n" +
        "    \"mfa_requirement\": {\n" +
        "      \"mfa_request_id\": \"" + MFA_REQUEST_ID + "\",\n" +
        "      \"mfa_constraints\": {\n" +
        "        \"" + MFA_KEY + "\": {\n" +
        "          \"any\": [\n" +
        "            {\n" +
        "              \"type\": \"" + MFA_METHOD_TYPE + "\",\n" +
        "              \"id\": \"" + MFA_METHOD_ID + "\",\n" +
        "              \"uses_passcode\": " + MFA_METHOD_USES_PASSCODE + ",\n" +
        "              \"name\": \"" + MFA_METHOD_NAME + "\"\n" +
        "            }\n" +
        "          ]\n" +
        "        }\n" +
        "      }\n" +
        "    }\n" +
        "  }\n" +
        "}";

    AuthResponseTest() {
        super(AuthResponse.class);
    }

    @Override
    protected AuthResponse createFull() {
        try {
            return objectMapper.readValue(RES_JSON, AuthResponse.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    @Test
    void testEqualsHashcodeMfa() {
        EqualsVerifier.simple().forClass(MfaRequirement.class).verify();
        EqualsVerifier.simple().forClass(MfaConstraintAny.class).verify();
        EqualsVerifier.simple().forClass(MfaMethodId.class).verify();
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        AuthResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(RES_JSON, AuthResponse.class),
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
        assertEquals(AUTH_NUM_USES, data.getNumUses(), "Incorrect auth num uses");
        assertEquals(2, data.getPolicies().size(), "Incorrect number of policies");
        assertTrue(data.getPolicies().containsAll(Set.of(AUTH_POLICY_1, AUTH_POLICY_2)));
        assertEquals(2, data.getTokenPolicies().size(), "Incorrect number of token policies");
        assertTrue(data.getTokenPolicies().containsAll(Set.of(AUTH_POLICY_2, AUTH_POLICY_1)), "Incorrect token policies");
        assertEquals(Map.of(AUTH_META_KEY, AUTH_META_VALUE), data.getMetadata(), "Incorrect auth metadata");

        assertEquals(MFA_REQUEST_ID, data.getMfaRequirement().getMfaRequestId(), "Incorrect MFA request ID");
        assertEquals(Set.of(MFA_KEY), data.getMfaRequirement().getMfaConstraints().keySet(), "Incorrect MFA constraint keys");
        var mfaConstraint = data.getMfaRequirement().getMfaConstraints().get(MFA_KEY);
        assertEquals(1, mfaConstraint.getAny().size(), "Incorrect number of any constraints");
        assertEquals(MFA_METHOD_TYPE, mfaConstraint.getAny().get(0).getType(), "Incorrect MFA method type");
        assertEquals(MFA_METHOD_ID, mfaConstraint.getAny().get(0).getId(), "Incorrect MFA method type");
        assertEquals(MFA_METHOD_USES_PASSCODE, mfaConstraint.getAny().get(0).getUsesPasscode(), "Incorrect MFA method uses passcode");
        assertEquals(MFA_METHOD_NAME, mfaConstraint.getAny().get(0).getName(), "Incorrect MFA method uses passcode");
    }
}
