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

import de.stklcode.jvault.connector.exception.InvalidResponseException;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link SecretListResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class SecretListResponseTest {
    private static final Map<String, Object> DATA = new HashMap<>();
    private static final String KEY1 = "key1";
    private static final String KEY2 = "key-2";
    private static final List<String> KEYS = Arrays.asList(KEY1, KEY2);

    static {
        DATA.put("keys", KEYS);
    }

    /**
     * Test getter, setter and get-methods for response data.
     *
     * @throws InvalidResponseException Should not occur
     */
    @Test
    void getKeysTest() throws InvalidResponseException {
        // Create empty Object.
        SecretListResponse res = new SecretListResponse();
        assertNull(res.getKeys(), "Keys should be null without initialization");

        // Provoke internal ClassCastException.
        Map<String, Object> invalidData = new HashMap<>();
        invalidData.put("keys", "some string");
        assertThrows(
                InvalidResponseException.class,
                () -> res.setData(invalidData),
                "Setting incorrect class succeeded"
        );

        // Fill correct data.
        res.setData(DATA);
        assertNotNull(res.getKeys(), "Keys should be filled here");
        assertEquals(2, res.getKeys().size(), "Unexpected number of keys");
        assertTrue(res.getKeys().containsAll(Set.of(KEY1, KEY2)), "Unexpected keys");
    }
}
