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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link SecretListResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class SecretListResponseTest extends AbstractModelTest<SecretListResponse> {
    private static final String KEY1 = "key1";
    private static final String KEY2 = "key-2";
    private static final String JSON = "{\n" +
            "  \"auth\": null,\n" +
            "  \"data\": {\n" +
            "    \"keys\": [" +
            "      \"" + KEY1 + "\",\n" +
            "      \"" + KEY2 + "\"\n" +
            "    ]\n" +
            "  },\n" +
            "  \"lease_duration\": 2764800,\n" +
            "  \"lease_id\": \"\",\n" +
            "  \"renewable\": false\n" +
            "}";

    SecretListResponseTest() {
        super(SecretListResponse.class);
    }

    @Override
    protected SecretListResponse createFull() {
        try {
            return new ObjectMapper().readValue(JSON, SecretListResponse.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    /**
     * Test JSON deserialization and key getter.
     */
    @Test
    void getKeysTest() {
        SecretListResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(JSON, SecretListResponse.class),
                "SecretListResponse deserialization failed"
        );

        assertEquals(List.of(KEY1, KEY2), res.getKeys(), "Unexpected secret keys");
    }
}
