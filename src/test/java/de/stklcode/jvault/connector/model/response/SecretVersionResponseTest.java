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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link SecretVersionResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class SecretVersionResponseTest extends AbstractModelTest<SecretVersionResponse> {
    private static final String CREATION_TIME = "2018-03-22T02:24:06.945319214Z";
    private static final String DELETION_TIME = "2018-03-22T02:36:43.986212308Z";
    private static final Integer VERSION = 42;

    private static final String META_JSON = "{\n" +
            "  \"data\": {\n" +
            "    \"created_time\": \"" + CREATION_TIME + "\",\n" +
            "    \"deletion_time\": \"" + DELETION_TIME + "\",\n" +
            "    \"destroyed\": false,\n" +
            "    \"version\": " + VERSION + "\n" +
            "  }\n" +
            "}";

    SecretVersionResponseTest() {
        super(SecretVersionResponse.class);
    }

    @Override
    protected SecretVersionResponse createFull() {
        try {
            return objectMapper.readValue(META_JSON, SecretVersionResponse.class);
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
        SecretVersionResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(META_JSON, SecretVersionResponse.class),
                "SecretVersionResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertNotNull(res.getMetadata(), "Parsed metadata is NULL");
        assertEquals(CREATION_TIME, res.getMetadata().getCreatedTimeString(), "Incorrect created time");
        assertEquals(DELETION_TIME, res.getMetadata().getDeletionTimeString(), "Incorrect deletion time");
        assertFalse(res.getMetadata().isDestroyed(), "Incorrect destroyed state");
        assertEquals(VERSION, res.getMetadata().getVersion(), "Incorrect version");
    }
}
