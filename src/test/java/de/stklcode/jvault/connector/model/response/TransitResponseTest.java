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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link TransitResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 1.5.0
 */
class TransitResponseTest extends AbstractModelTest<TransitResponse> {
    private static final String CIPHERTEXT = "vault:v1:XjsPWPjqPrBi1N2Ms2s1QM798YyFWnO4TR4lsFA=";
    private static final String PLAINTEXT = "dGhlIHF1aWNrIGJyb3duIGZveAo=";
    private static final String SUM = "dGhlIHF1aWNrIGJyb3duIGZveAo=";

    TransitResponseTest() {
        super(TransitResponse.class);
    }

    @Override
    protected TransitResponse createFull() {
        return assertDoesNotThrow(
            () -> objectMapper.readValue(
                json(
                    "\"ciphertext\": \"" + CIPHERTEXT + "\", " +
                        "\"plaintext\": \"" + PLAINTEXT + "\", " +
                        "\"sum\": \"" + SUM + "\""
                ),
                TransitResponse.class
            ),
            "Creation of full model failed"
        );
    }

    @Test
    void encryptionTest() {
        TransitResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(
                json("\"ciphertext\": \"" + CIPHERTEXT + "\""),
                TransitResponse.class
            ),
            "TransitResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals("987c6daf-b0e2-4142-a970-1e61fdb249d7", res.getRequestId(), "Incorrect request id");
        assertEquals("", res.getLeaseId(), "Unexpected lease id");
        assertFalse(res.isRenewable(), "Unexpected renewable flag");
        assertEquals(0, res.getLeaseDuration(), "Unexpected lease duration");
        assertEquals(CIPHERTEXT, res.getCiphertext(), "Incorrect ciphertext");
        assertNull(res.getPlaintext(), "Unexpected plaintext");
        assertNull(res.getSum(), "Unexpected sum");
        assertNull(res.getWrapInfo(), "Unexpected wrap info");
        assertNull(res.getWarnings(), "Unexpected warnings");
        assertNull(res.getAuth(), "Unexpected auth");
    }

    @Test
    void decryptionTest() {
        TransitResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(
                json("\"plaintext\": \"" + PLAINTEXT + "\""),
                TransitResponse.class
            ),
            "TransitResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals("987c6daf-b0e2-4142-a970-1e61fdb249d7", res.getRequestId(), "Incorrect request id");
        assertEquals("", res.getLeaseId(), "Unexpected lease id");
        assertFalse(res.isRenewable(), "Unexpected renewable flag");
        assertEquals(0, res.getLeaseDuration(), "Unexpected lease duration");
        assertNull(res.getCiphertext(), "Unexpected ciphertext");
        assertEquals(PLAINTEXT, res.getPlaintext(), "Incorrect plaintext");
        assertNull(res.getSum(), "Unexpected sum");
        assertNull(res.getWrapInfo(), "Unexpected wrap info");
        assertNull(res.getWarnings(), "Unexpected warnings");
        assertNull(res.getAuth(), "Unexpected auth");
    }

    @Test
    void hashTest() {
        TransitResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(
                json("\"sum\": \"" + SUM + "\""),
                TransitResponse.class
            ),
            "TransitResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals("987c6daf-b0e2-4142-a970-1e61fdb249d7", res.getRequestId(), "Incorrect request id");
        assertEquals("", res.getLeaseId(), "Unexpected lease id");
        assertFalse(res.isRenewable(), "Unexpected renewable flag");
        assertEquals(0, res.getLeaseDuration(), "Unexpected lease duration");
        assertNull(res.getCiphertext(), "Unexpected ciphertext");
        assertNull(res.getPlaintext(), "Unexpected plaintext");
        assertEquals(SUM, res.getSum(), "Incorrect sum");
        assertNull(res.getWrapInfo(), "Unexpected wrap info");
        assertNull(res.getWarnings(), "Unexpected warnings");
        assertNull(res.getAuth(), "Unexpected auth");
    }

    private static String json(String data) {
        return "{\n" +
            "  \"request_id\" : \"987c6daf-b0e2-4142-a970-1e61fdb249d7\",\n" +
            "  \"lease_id\" : \"\",\n" +
            "  \"renewable\" : false,\n" +
            "  \"lease_duration\" : 0,\n" +
            "  \"data\" : {\n" +
            "    " + data + "\n" +
            "  },\n" +
            "  \"wrap_info\" : null,\n" +
            "  \"warnings\" : null,\n" +
            "  \"auth\" : null\n" +
            "}";
    }
}
