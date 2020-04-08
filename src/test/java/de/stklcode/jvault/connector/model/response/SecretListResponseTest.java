/*
 * Copyright 2016-2020 Stefan Kalscheuer
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit Test for {@link SecretListResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
public class SecretListResponseTest {
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
    public void getKeysTest() throws InvalidResponseException {
        // Create empty Object.
        SecretListResponse res = new SecretListResponse();
        assertThat("Keys should be null without initialization", res.getKeys(), is(nullValue()));

        // Provoke internal ClassCastException.
        try {
            Map<String, Object> invalidData = new HashMap<>();
            invalidData.put("keys", "some string");
            res.setData(invalidData);
            fail("Setting incorrect class succeeded");
        } catch (Exception e) {
            assertThat("Unexpected exception type", e, instanceOf(InvalidResponseException.class));
        }

        // Fill correct data.
        res.setData(DATA);
        assertThat("Keys should be filled here", res.getKeys(), is(notNullValue()));
        assertThat("Unexpected number of keys", res.getKeys(), hasSize(2));
        assertThat("Unexpected keys", res.getKeys(), contains(KEY1, KEY2));
    }
}
