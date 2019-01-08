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
 * JUnit Test for {@link SecretResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
public class SecretResponseTest {
    private static final Map<String, Object> DATA = new HashMap<>();
    private static final String KEY_UNKNOWN = "unknown";
    private static final String KEY_STRING = "test1";
    private static final String VAL_STRING = "testvalue";
    private static final String KEY_INTEGER = "test2";
    private static final Integer VAL_INTEGER = 42;
    private static final String KEY_LIST = "list";
    private static final String VAL_LIST = "[\"first\",\"second\"]";

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


    static {
        DATA.put(KEY_STRING, VAL_STRING);
        DATA.put(KEY_INTEGER, VAL_INTEGER);
        DATA.put(KEY_LIST, VAL_LIST);
    }

    /**
     * Test getter, setter and get-methods for response data.
     *
     * @throws InvalidResponseException Should not occur
     */
    @Test
    @SuppressWarnings("unchecked")
    public void getDataRoundtrip() throws InvalidResponseException {
        // Create empty Object.
        SecretResponse res = new SecretResponse();
        assertThat("Initial data should be Map", res.getData(), is(instanceOf(Map.class)));
        assertThat("Initial data should be empty", res.getData().entrySet(), empty());
        assertThat("Getter should return NULL on empty data map", res.get(KEY_STRING), is(nullValue()));

        // Fill data map.
        res.setData(DATA);
        assertThat("Data setter/getter not transparent", res.getData(), is(DATA));
        assertThat("Data size modified", res.getData().keySet(), hasSize(DATA.size()));
        assertThat("Data keys not passed correctly", res.getData().keySet(), containsInAnyOrder(KEY_STRING, KEY_INTEGER, KEY_LIST));
        assertThat("Data values not passed correctly", res.get(KEY_STRING), is(VAL_STRING));
        assertThat("Data values not passed correctly", res.get(KEY_INTEGER), is(VAL_INTEGER));
        assertThat("Non-Null returned on unknown key", res.get(KEY_UNKNOWN), is(nullValue()));

        // Try explicit JSON conversion.
        final List list = res.get(KEY_LIST, List.class);
        assertThat("JSON parsing of list failed", list, is(notNullValue()));
        assertThat("JSON parsing of list returned incorrect size", list.size(), is(2));
        assertThat("JSON parsing of list returned incorrect elements", (List<Object>)list, contains("first", "second"));
        assertThat("Non-Null returned on unknown key", res.get(KEY_UNKNOWN, Object.class), is(nullValue()));

        // Requesting invalid class should result in Exception.
        try {
            res.get(KEY_LIST, Double.class);
            fail("JSON parsing to incorrect type succeeded.");
        } catch (Exception e) {
            assertThat(e, is(instanceOf(InvalidResponseException.class)));
        }
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    public void jsonRoundtrip() {
        try {
            SecretResponse res = new ObjectMapper().readValue(SECRET_JSON, SecretResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            assertThat("Incorrect lease ID", res.getLeaseId(), is(SECRET_LEASE_ID));
            assertThat("Incorrect lease duration", res.getLeaseDuration(), is(SECRET_LEASE_DURATION));
            assertThat("Incorrect renewable status", res.isRenewable(), is(SECRET_RENEWABLE));
            assertThat("Incorrect warnings", res.getWarnings(), is(SECRET_WARNINGS));
            assertThat("Response does not contain correct data", res.get(SECRET_DATA_K1), is(SECRET_DATA_V1));
            assertThat("Response does not contain correct data", res.get(SECRET_DATA_K2), is(SECRET_DATA_V2));
        } catch (IOException e) {
            fail("SecretResponse deserialization failed: " + e.getMessage());
        }
    }
}
