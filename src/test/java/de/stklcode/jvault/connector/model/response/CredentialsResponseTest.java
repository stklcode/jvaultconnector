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

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * JUnit Test for {@link CredentialsResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class CredentialsResponseTest {
    private static final Map<String, Object> DATA = new HashMap<>();
    private static final String VAL_USER = "testUserName";
    private static final String VAL_PASS = "5up3r5ecr3tP455";

    static {
        DATA.put("username", VAL_USER);
        DATA.put("password", VAL_PASS);
    }

    /**
     * Test getter, setter and get-methods for response data.
     *
     * @throws InvalidResponseException Should not occur
     */
    @Test
    @SuppressWarnings("unchecked")
    void getCredentialsTest() throws InvalidResponseException {
        // Create empty Object.
        CredentialsResponse res = new CredentialsResponse();
        assertNull(res.getUsername(), "Username not present in data map should not return anything");
        assertNull(res.getPassword(), "Password not present in data map should not return anything");

        // Fill data map.
        res.setData(DATA);
        assertEquals(VAL_USER, res.getUsername(), "Incorrect username");
        assertEquals(VAL_PASS, res.getPassword(), "Incorrect password");
    }
}
