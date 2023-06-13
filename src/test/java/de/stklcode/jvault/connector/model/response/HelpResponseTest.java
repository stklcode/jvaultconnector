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

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link HelpResponse} model.
 *
 * @author Stefan Kalscheuer
 */
class HelpResponseTest extends AbstractModelTest<HelpResponse> {
    private static final String HELP = "Help Text.";

    private static final String JSON = "{\"help\":\"" + HELP + "\"}";

    HelpResponseTest() {
        super(HelpResponse.class);
    }

    @Override
    protected HelpResponse createFull() {
        try {
            return objectMapper.readValue(JSON, HelpResponse.class);
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
        HelpResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(JSON, HelpResponse.class),
                "HelpResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(HELP, res.getHelp(), "Unexpected help text");
        assertEquals(
                JSON,
                assertDoesNotThrow(() -> objectMapper.writeValueAsString(res), "HelpResponse serialization failed"),
                "Unexpected JSON string after serialization"
        );
    }
}
