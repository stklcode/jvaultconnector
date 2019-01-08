/*
 * Copyright 2016-2019 Stefan Kalscheuer
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

import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit Test for {@link CredentialsResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
public class CredentialsResponseTest {
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
    public void getCredentialsTest() throws InvalidResponseException {
        // Create empty Object.
        CredentialsResponse res = new CredentialsResponse();
        assertThat("Username not present in data map should not return anything", res.getUsername(), is(nullValue()));
        assertThat("Password not present in data map should not return anything", res.getPassword(), is(nullValue()));

        // Fill data map.
        res.setData(DATA);
        assertThat("Incorrect username", res.getUsername(), is(VAL_USER));
        assertThat("Incorrect password", res.getPassword(), is(VAL_PASS));
    }
}
