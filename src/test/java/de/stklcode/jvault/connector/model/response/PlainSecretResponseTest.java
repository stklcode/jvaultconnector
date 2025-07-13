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

import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import java.util.*;

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
        return assertDoesNotThrow(
            () -> objectMapper.readValue(SECRET_JSON, PlainSecretResponse.class),
            "Creation of full model instance failed"
        );
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        SecretResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(SECRET_JSON, PlainSecretResponse.class),
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

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void testGetter() {
        final var stringKey = "string";
        final var stringVal = "test";

        final var numberKey = "number";
        final var numberVal = 123.45;

        final var listKey = "list";
        final var listVal = List.of("foo", "bar");

        final var complexKey = "complex";
        final var complexVal = new ComplexType("val1", 678);

        SecretResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(
                "{\n" +
                    "  \"request_id\": \"req-id\",\n" +
                    "  \"lease_id\": \"lea-id\",\n" +
                    "  \"lease_duration\": " + 123456 + ",\n" +
                    "  \"renewable\": true,\n" +
                    "  \"data\": {\n" +
                    "    \"" + stringKey + "\": \"" + stringVal + "\",\n" +
                    "    \"" + numberKey + "\": \"" + numberVal + "\",\n" +
                    "    \"" + listKey + "\": [\"" + String.join("\", \"", listVal) + "\"],\n" +
                    "    \"" + complexKey + "\": {" +
                    "      \"field1\": \"" + complexVal.field1 + "\",\n" +
                    "      \"field2\": " + complexVal.field2 + "\n" +
                    "    },\n" +
                    "    \"" + complexKey + "Json\": \"" + objectMapper.writeValueAsString(complexVal).replace("\"", "\\\"") + "\"\n" +
                    "  }\n" +
                    "}",
                PlainSecretResponse.class
            ),
            "SecretResponse deserialization failed"
        );

        assertEquals(stringVal, res.get(stringKey), "unexpected value for string (implicit)");
        assertEquals(
            stringVal,
            assertDoesNotThrow(() -> res.get(stringKey, String.class), "getting string failed"),
            "unexpected value for string (explicit)"
        );

        assertEquals(String.valueOf(numberVal), res.get(numberKey), "unexpected value for number (implicit)");
        assertEquals(
            numberVal,
            assertDoesNotThrow(() -> res.get(numberKey, Double.class), "getting number failed"),
            "unexpected value for number (explicit)"
        );
        assertEquals(
            String.valueOf(numberVal),
            assertDoesNotThrow(() -> res.get(numberKey, String.class), "getting number as string failed"),
            "unexpected value for number as string (explicit)"
        );

        assertEquals(listVal, res.get(listKey), "unexpected value for list (implicit)");
        assertEquals(
            listVal,
            assertDoesNotThrow(() -> res.get(listKey, ArrayList.class), "getting list failed"),
            "unexpected value for list (explicit)"
        );

        assertEquals(complexVal.toMap(), res.get(complexKey), "unexpected value for complex type (implicit)");
        assertEquals(
            complexVal.toMap(),
            assertDoesNotThrow(() -> res.get(complexKey, HashMap.class), "getting complex type as map failed"),
            "unexpected value for complex type as map (explicit)"
        );
        assertEquals(
            complexVal,
            assertDoesNotThrow(() -> res.get(complexKey, ComplexType.class), "getting complex type failed"),
            "unexpected value for complex type (explicit)"
        );
        assertThrows(
            InvalidResponseException.class,
            () -> res.get(complexKey, Integer.class),
            "getting complex type as integer should fail"
        );
        assertEquals(
            complexVal,
            assertDoesNotThrow(() -> res.get(complexKey + "Json", ComplexType.class), "getting complex type from JSON string failed"),
            "unexpected value for complex type from JSON string"
        );
    }


    /**
     * Test class for complex field mapping.
     */
    private static class ComplexType {
        @JsonProperty("field1")
        private String field1;

        @JsonProperty("field2")
        private Integer field2;

        private ComplexType() {
            // Required for JSON deserialization.
        }

        private ComplexType(String field1, Integer field2) {
            this.field1 = field1;
            this.field2 = field2;
        }

        private Map<String, Object> toMap() {
            return Map.of(
                "field1", field1,
                "field2", field2
            );
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            } else if (o == null || getClass() != o.getClass()) {
                return false;
            }
            ComplexType that = (ComplexType) o;
            return Objects.equals(field1, that.field1) && Objects.equals(field2, that.field2);
        }

        @Override
        public int hashCode() {
            return Objects.hash(field1, field2);
        }
    }
}
