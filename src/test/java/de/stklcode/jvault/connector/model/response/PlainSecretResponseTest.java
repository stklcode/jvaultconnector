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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link PlainSecretResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class PlainSecretResponseTest extends AbstractModelTest<PlainSecretResponse> {
    private static final String SECRET_REQUEST_ID = "68315073-6658-e3ff-2da7-67939fb91bbd";
    private static final String SECRET_LEASE_ID = "";
    private static final Integer SECRET_LEASE_DURATION = 2764800;
    private static final boolean SECRET_RENEWABLE = false;
    private static final String SECRET_DATA_K1 = "excited";
    private static final String SECRET_DATA_V1 = "yes";
    private static final String SECRET_DATA_K2 = "value";
    private static final String SECRET_DATA_V2 = "world";
    private static final List<String> SECRET_WARNINGS = null;
    private static final String SECRET_JSON = "{\n" +
            "    \"request_id\": \"" + SECRET_REQUEST_ID + "\",\n" +
            "    \"lease_id\": \"" + SECRET_LEASE_ID + "\",\n" +
            "    \"lease_duration\": " + SECRET_LEASE_DURATION + ",\n" +
            "    \"renewable\": " + SECRET_RENEWABLE + ",\n" +
            "    \"data\": {\n" +
            "        \"" + SECRET_DATA_K1 + "\": \"" + SECRET_DATA_V1 + "\",\n" +
            "        \"" + SECRET_DATA_K2 + "\": \"" + SECRET_DATA_V2 + "\"\n" +
            "    },\n" +
            "    \"warnings\": " + SECRET_WARNINGS + "\n" +
            "}";

    PlainSecretResponseTest() {
        super(PlainSecretResponse.class);
    }

    @Override
    protected PlainSecretResponse createFull() {
        try {
            return new ObjectMapper().readValue(SECRET_JSON, PlainSecretResponse.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        SecretResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(SECRET_JSON, PlainSecretResponse.class),
                "SecretResponse deserialization failed"
        );

        assertNotNull(res, "Parsed response is NULL");
        assertEquals(SECRET_REQUEST_ID, res.getRequestId(), "Incorrect request ID");
        assertEquals(SECRET_LEASE_ID, res.getLeaseId(), "Incorrect lease ID");
        assertEquals(SECRET_LEASE_DURATION, res.getLeaseDuration(), "Incorrect lease duration");
        assertEquals(SECRET_RENEWABLE, res.isRenewable(), "Incorrect renewable status");
        assertEquals(SECRET_WARNINGS, res.getWarnings(), "Incorrect warnings");
        assertEquals(SECRET_DATA_V1, res.get(SECRET_DATA_K1), "Response does not contain correct data");
        assertEquals(SECRET_DATA_V2, res.get(SECRET_DATA_K2), "Response does not contain correct data");
    }
}
