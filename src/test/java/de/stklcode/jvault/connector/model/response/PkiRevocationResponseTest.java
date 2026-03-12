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

package de.stklcode.jvault.connector.model.response;

import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link PkiRevocationResponse} model.
 *
 * @author Stefan Kalscheuer
 */
class PkiRevocationResponseTest extends AbstractModelTest<PkiRevocationResponse> {
    private static final String LEASE_ID = "pki/revoke/test/0215cc7e-cadd-4553-baab-25869500a772";
    private static final Boolean RES_RENEWABLE = false;
    private static final Integer RES_LEASE_DURATION = 21600;
    private static final Long REVOCATION_TIME = 1784147440L;
    private static final String REVOCATION_TIME_RFC3339 = "2026-07-15T20:30:40Z";
    private static final String STATE = "revoked";

    private static final String RES_JSON = "{\n" +
        "  \"lease_id\": \"" + LEASE_ID + "\",\n" +
        "  \"renewable\": " + RES_RENEWABLE + ",\n" +
        "  \"lease_duration\": " + RES_LEASE_DURATION + ",\n" +
        "  \"data\": {\n" +
        "    \"revocation_time\": \"" + REVOCATION_TIME + "\",\n" +
        "    \"revocation_time_rfc3339\": \"" + REVOCATION_TIME_RFC3339 + "\",\n" +
        "    \"state\": \"" + STATE + "\"\n" +
        "  },\n" +
        "  \"warnings\": null,\n" +
        "  \"auth\": null\n" +
        "}";

    PkiRevocationResponseTest() {
        super(PkiRevocationResponse.class);
    }

    @Override
    protected PkiRevocationResponse createFull() {
        return assertDoesNotThrow(
            () -> objectMapper.readValue(RES_JSON, PkiRevocationResponse.class),
            "Creation of full model instance failed"
        );
    }

    @Test
    void jsonRoundtrip() {
        PkiRevocationResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_JSON, PkiRevocationResponse.class),
            "PkiResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(LEASE_ID, res.responseHeader().leaseId(), "Incorrect leaseId");
        assertEquals(RES_RENEWABLE, res.responseHeader().renewable(), "Incorrect response renewable flag");
        assertEquals(RES_LEASE_DURATION, res.responseHeader().leaseDuration(), "Incorrect leaseDuration");
        assertNull(res.responseHeader().warnings(), "Incorrect warnings");
        assertNull(res.responseHeader().mountType(), "Incorrect mount type");

        PkiRevocationResponse.Data data = res.data();
        assertNotNull(data, "PKI data is NULL");
        assertEquals(REVOCATION_TIME, data.revocationTime(), "Incorrect revocationTime");
        assertEquals(REVOCATION_TIME_RFC3339, data.revocationTimeRFC3339(), "Incorrect revocationTimeRFC3339");
        assertEquals(STATE, data.state(), "Incorrect state");
    }
}
