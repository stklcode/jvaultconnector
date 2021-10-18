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

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link MetadataResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class MetadataResponseTest {
    private static final String V1_TIME = "2018-03-22T02:24:06.945319214Z";
    private static final String V3_TIME = "2018-03-22T02:36:43.986212308Z";
    private static final String V2_TIME = "2018-03-22T02:36:33.954880664Z";
    private static final Integer CURRENT_VERSION = 3;
    private static final Integer MAX_VERSIONS = 0;
    private static final Integer OLDEST_VERSION = 1;

    private static final String META_JSON = "{\n" +
            "  \"data\": {\n" +
            "    \"created_time\": \"" + V1_TIME + "\",\n" +
            "    \"current_version\": " + CURRENT_VERSION + ",\n" +
            "    \"max_versions\": " + MAX_VERSIONS + ",\n" +
            "    \"oldest_version\": " + OLDEST_VERSION + ",\n" +
            "    \"updated_time\": \"" + V3_TIME + "\",\n" +
            "    \"versions\": {\n" +
            "      \"1\": {\n" +
            "        \"created_time\": \"" + V1_TIME + "\",\n" +
            "        \"deletion_time\": \"" + V2_TIME + "\",\n" +
            "        \"destroyed\": true\n" +
            "      },\n" +
            "      \"2\": {\n" +
            "        \"created_time\": \"" + V2_TIME + "\",\n" +
            "        \"deletion_time\": \"\",\n" +
            "        \"destroyed\": false\n" +
            "      },\n" +
            "      \"3\": {\n" +
            "        \"created_time\": \"" + V3_TIME + "\",\n" +
            "        \"deletion_time\": \"\",\n" +
            "        \"destroyed\": false\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}";

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        MetadataResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(META_JSON, MetadataResponse.class),
                "MetadataResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertNotNull(res.getMetadata(), "Parsed metadata is NULL");
        assertEquals(V1_TIME, res.getMetadata().getCreatedTimeString(), "Incorrect created time");
        assertNotNull(res.getMetadata().getCreatedTime(), "Parting created time failed");
        assertEquals(CURRENT_VERSION, res.getMetadata().getCurrentVersion(), "Incorrect current version");
        assertEquals(MAX_VERSIONS, res.getMetadata().getMaxVersions(), "Incorrect max versions");
        assertEquals(OLDEST_VERSION, res.getMetadata().getOldestVersion(), "Incorrect oldest version");
        assertEquals(V3_TIME, res.getMetadata().getUpdatedTimeString(), "Incorrect updated time");
        assertNotNull(res.getMetadata().getUpdatedTime(), "Parting updated time failed");
        assertEquals(3, res.getMetadata().getVersions().size(), "Incorrect number of versions");
        assertEquals(V2_TIME, res.getMetadata().getVersions().get(1).getDeletionTimeString(), "Incorrect version 1 delete time");
        assertNotNull(res.getMetadata().getVersions().get(1).getDeletionTime(), "Parsing version delete time failed");
        assertTrue(res.getMetadata().getVersions().get(1).isDestroyed(), "Incorrect version 1 destroyed state");
        assertEquals(V2_TIME, res.getMetadata().getVersions().get(2).getCreatedTimeString(), "Incorrect version 2 created time");
        assertNotNull(res.getMetadata().getVersions().get(2).getCreatedTime(), "Parsing version created failed");
        assertFalse(res.getMetadata().getVersions().get(3).isDestroyed(), "Incorrect version 3 destroyed state");
    }

    @Test
    void testEqualsHashcode() {
        EqualsVerifier.simple().forClass(MetadataResponse.class).verify();
    }
}
