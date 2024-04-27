/*
 * Copyright 2016-2024 Stefan Kalscheuer
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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link MetaSecretResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
class MetaSecretResponseTest extends AbstractModelTest<MetaSecretResponse> {
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
    private static final String CUSTOM_META_KEY = "foo";
    private static final String CUSTOM_META_VAL = "bar";

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
            "          \"custom_metadata\": null,\n" +
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
            "          \"custom_metadata\": {" +
            "            \"" + CUSTOM_META_KEY + "\": \"" + CUSTOM_META_VAL + "\"" +
            "          },\n" +
            "          \"deletion_time\": \"" + SECRET_META_DELETED + "\",\n" +
            "          \"destroyed\": true,\n" +
            "          \"version\": 2\n" +
            "      }\n" +
            "    },\n" +
            "    \"warnings\": " + SECRET_WARNINGS + "\n" +
            "}";

    MetaSecretResponseTest() {
        super(MetaSecretResponse.class);
    }

    @Override
    protected MetaSecretResponse createFull() {
        try {
            return objectMapper.readValue(SECRET_JSON_V2, MetaSecretResponse.class);
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
        // KV v2 secret.
        MetaSecretResponse res = assertDoesNotThrow(
                () -> objectMapper.readValue(SECRET_JSON_V2, MetaSecretResponse.class),
                "SecretResponse deserialization failed"
        );
        assertSecretData(res);
        assertNotNull(res.getMetadata(), "SecretResponse does not contain metadata");
        assertNotNull(res.getMetadata().getCreatedTime(), "Creation date parsing failed");
        assertNull(res.getMetadata().getDeletionTime(), "Incorrect deletion date");
        assertFalse(res.getMetadata().isDestroyed(), "Secret destroyed when not expected");
        assertEquals(1, res.getMetadata().getVersion(), "Incorrect secret version");
        assertNull(res.getMetadata().getCustomMetadata(), "Incorrect custom metadata");

        // Deleted KV v2 secret.
        res = assertDoesNotThrow(
                () -> objectMapper.readValue(SECRET_JSON_V2_2, MetaSecretResponse.class),
                "SecretResponse deserialization failed"
        );
        assertSecretData(res);
        assertNotNull(res.getMetadata(), "SecretResponse does not contain metadata");
        assertNotNull(res.getMetadata().getCreatedTime(), "Creation date parsing failed");
        assertNotNull(res.getMetadata().getDeletionTime(), "Incorrect deletion date");
        assertTrue(res.getMetadata().isDestroyed(), "Secret destroyed when not expected");
        assertEquals(2, res.getMetadata().getVersion(), "Incorrect secret version");
        assertEquals(Map.of(CUSTOM_META_KEY, CUSTOM_META_VAL), res.getMetadata().getCustomMetadata(), "Incorrect custom metadata");
    }

    private void assertSecretData(SecretResponse res) {
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(SECRET_REQUEST_ID, res.getRequestId(), "Incorrect request ID");
        assertEquals(SECRET_LEASE_ID, res.getLeaseId(), "Incorrect lease ID");
        assertEquals(SECRET_LEASE_DURATION, res.getLeaseDuration(), "Incorrect lease duration");
        assertEquals(SECRET_RENEWABLE, res.isRenewable(), "Incorrect renewable status");
        assertEquals(SECRET_WARNINGS, res.getWarnings(), "Incorrect warnings");
        assertEquals(SECRET_DATA_V1, res.get(SECRET_DATA_K1), "Response does not contain correct data");
        assertEquals(SECRET_DATA_V2, res.get(SECRET_DATA_K2), "Response does not contain correct data");
    }
}
