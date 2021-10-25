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

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link SecretResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class SecretResponseTest {
    private static final String SECRET_REQUEST_ID = "68315073-6658-e3ff-2da7-67939fb91bbd";
    private static final String SECRET_LEASE_ID = "";
    private static final Integer SECRET_LEASE_DURATION = 2764800;
    private static final boolean SECRET_RENEWABLE = false;
    private static final String SECRET_DATA_K1 = "excited";
    private static final String SECRET_DATA_V1 = "yes";
    private static final String SECRET_DATA_K2 = "value";
    private static final String SECRET_DATA_V2 = "world";
    private static final String SECRET_META_CREATED = "2018-03-22T02:24:06.945319214Z";
    private static final String SECRET_META_DELETED = "2018-03-23T03:25:07.056420325Z";
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
    private static final String SECRET_JSON_V2 = "{\n" +
            "    \"request_id\": \"" + SECRET_REQUEST_ID + "\",\n" +
            "    \"lease_id\": \"" + SECRET_LEASE_ID + "\",\n" +
            "    \"lease_duration\": " + SECRET_LEASE_DURATION + ",\n" +
            "    \"renewable\": " + SECRET_RENEWABLE + ",\n" +
            "    \"data\": {\n" +
            "      \"data\": {\n" +
            "          \"" + SECRET_DATA_K1 + "\": \"" + SECRET_DATA_V1 + "\",\n" +
            "          \"" + SECRET_DATA_K2 + "\": \"" + SECRET_DATA_V2 + "\"\n" +
            "      },\n" +
            "      \"metadata\": {\n" +
            "          \"created_time\": \"" + SECRET_META_CREATED + "\",\n" +
            "          \"deletion_time\": \"\",\n" +
            "          \"destroyed\": false,\n" +
            "          \"version\": 1\n" +
            "      }\n" +
            "    },\n" +
            "    \"warnings\": " + SECRET_WARNINGS + "\n" +
            "}";
    private static final String SECRET_JSON_V2_2 = "{\n" +
            "    \"request_id\": \"" + SECRET_REQUEST_ID + "\",\n" +
            "    \"lease_id\": \"" + SECRET_LEASE_ID + "\",\n" +
            "    \"lease_duration\": " + SECRET_LEASE_DURATION + ",\n" +
            "    \"renewable\": " + SECRET_RENEWABLE + ",\n" +
            "    \"data\": {\n" +
            "      \"data\": {\n" +
            "          \"" + SECRET_DATA_K1 + "\": \"" + SECRET_DATA_V1 + "\",\n" +
            "          \"" + SECRET_DATA_K2 + "\": \"" + SECRET_DATA_V2 + "\"\n" +
            "      },\n" +
            "      \"metadata\": {\n" +
            "          \"created_time\": \"" + SECRET_META_CREATED + "\",\n" +
            "          \"deletion_time\": \"" + SECRET_META_DELETED + "\",\n" +
            "          \"destroyed\": true,\n" +
            "          \"version\": 2\n" +
            "      }\n" +
            "    },\n" +
            "    \"warnings\": " + SECRET_WARNINGS + "\n" +
            "}";

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        SecretResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(SECRET_JSON, PlainSecretResponse.class),
                "SecretResponse deserialization failed"
        );
        assertSecretData(res);

        // KV v2 secret.
        res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(SECRET_JSON_V2, MetaSecretResponse.class),
                "SecretResponse deserialization failed"
        );
        assertSecretData(res);
        assertNotNull(res.getMetadata(), "SecretResponse does not contain metadata");
        assertEquals(SECRET_META_CREATED, res.getMetadata().getCreatedTimeString(), "Incorrect creation date string");
        assertNotNull(res.getMetadata().getCreatedTime(), "Creation date parsing failed");
        assertEquals("", res.getMetadata().getDeletionTimeString(), "Incorrect deletion date string");
        assertNull(res.getMetadata().getDeletionTime(), "Incorrect deletion date");
        assertFalse(res.getMetadata().isDestroyed(), "Secret destroyed when not expected");
        assertEquals(1, res.getMetadata().getVersion(), "Incorrect secret version");

        // Deleted KV v2 secret.
        res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(SECRET_JSON_V2_2, MetaSecretResponse.class),
                "SecretResponse deserialization failed"
        );
        assertSecretData(res);
        assertNotNull(res.getMetadata(), "SecretResponse does not contain metadata");
        assertEquals(SECRET_META_CREATED, res.getMetadata().getCreatedTimeString(), "Incorrect creation date string");
        assertNotNull(res.getMetadata().getCreatedTime(), "Creation date parsing failed");
        assertEquals(SECRET_META_DELETED, res.getMetadata().getDeletionTimeString(), "Incorrect deletion date string");
        assertNotNull(res.getMetadata().getDeletionTime(), "Incorrect deletion date");
        assertTrue(res.getMetadata().isDestroyed(), "Secret destroyed when not expected");
        assertEquals(2, res.getMetadata().getVersion(), "Incorrect secret version");
    }

    @Test
    void testEqualsHashcode() {
        EqualsVerifier.simple().forClass(SecretResponse.class).verify();
        EqualsVerifier.simple().forClass(PlainSecretResponse.class).verify();
        EqualsVerifier.simple().forClass(MetaSecretResponse.class).verify();
    }

    private void assertSecretData(SecretResponse res) {
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(SECRET_LEASE_ID, res.getLeaseId(), "Incorrect lease ID");
        assertEquals(SECRET_LEASE_DURATION, res.getLeaseDuration(), "Incorrect lease duration");
        assertEquals(SECRET_RENEWABLE, res.isRenewable(), "Incorrect renewable status");
        assertEquals(SECRET_WARNINGS, res.getWarnings(), "Incorrect warnings");
        assertEquals(SECRET_DATA_V1, res.get(SECRET_DATA_K1), "Response does not contain correct data");
        assertEquals(SECRET_DATA_V2, res.get(SECRET_DATA_K2), "Response does not contain correct data");
    }
}
