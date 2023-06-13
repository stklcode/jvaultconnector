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
import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link ErrorResponse} model.
 *
 * @author Stefan Kalscheuer
 */
class ErrorResponseTest extends AbstractModelTest<ErrorResponse> {
    private static final String ERROR_1 = "Error #1";
    private static final String ERROR_2 = "Error #2";

    private static final String JSON = "{\"errors\":[\"" + ERROR_1 + "\",\"" + ERROR_2 + "\"]}";
    private static final String JSON_EMPTY = "{\"errors\":[]}";

    ErrorResponseTest() {
        super(ErrorResponse.class);
    }

    @Override
    protected ErrorResponse createFull() {
        try {
            return objectMapper.readValue(JSON, ErrorResponse.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    /**
     * Test creation from JSON value as returned by Vault.
     */
    @Test
    void jsonRoundtrip() {
        ErrorResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(JSON, ErrorResponse.class),
                "ErrorResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(List.of(ERROR_1, ERROR_2), res.getErrors(), "Unexpected error messages");
        assertEquals(
                JSON,
                assertDoesNotThrow(() -> objectMapper.writeValueAsString(res), "ErrorResponse serialization failed"),
                "Unexpected JSON string after serialization"
        );
    }


    @Test
    void testToString() {
        ErrorResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(JSON, ErrorResponse.class),
                "ErrorResponse deserialization failed"
        );
        assertEquals(ERROR_1, res.toString());

        res = assertDoesNotThrow(
                () -> objectMapper.readValue(JSON_EMPTY, ErrorResponse.class),
                "ErrorResponse deserialization failed with empty list"
        );
        assertEquals("error response", res.toString());

        assertEquals("error response", new ErrorResponse().toString());
    }
}
