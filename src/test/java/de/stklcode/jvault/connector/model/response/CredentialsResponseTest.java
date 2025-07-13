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
 * JUnit Test for {@link CredentialsResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class CredentialsResponseTest extends AbstractModelTest<CredentialsResponse> {
    private static final String VAL_USER = "testUserName";
    private static final String VAL_PASS = "5up3r5ecr3tP455";
    private static final String JSON = "{\n" +
            "    \"request_id\": \"68315073-6658-e3ff-2da7-67939fb91bbd\",\n" +
            "    \"lease_id\": \"\",\n" +
            "    \"lease_duration\": 2764800,\n" +
            "    \"renewable\": false,\n" +
            "    \"data\": {\n" +
            "        \"username\": \"" + VAL_USER + "\",\n" +
            "        \"password\": \"" + VAL_PASS + "\"\n" +
            "    },\n" +
            "    \"warnings\": null\n" +
            "}";

    CredentialsResponseTest() {
        super(CredentialsResponse.class);
    }

    @Override
    protected CredentialsResponse createFull() {
        return assertDoesNotThrow(
            () -> objectMapper.readValue(JSON, CredentialsResponse.class),
            "Creation of full model instance failed"
        );
    }

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    void getCredentialsTest() {
        // Create empty Object.
        CredentialsResponse res = new CredentialsResponse();
        assertNull(res.getUsername(), "Username not present in data map should not return anything");
        assertNull(res.getPassword(), "Password not present in data map should not return anything");

        res = assertDoesNotThrow(
                () -> objectMapper.readValue(JSON, CredentialsResponse.class),
                "Deserialization of CredentialsResponse failed"
        );
        assertEquals(VAL_USER, res.getUsername(), "Incorrect username");
        assertEquals(VAL_PASS, res.getPassword(), "Incorrect password");
    }
}
