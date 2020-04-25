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

import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit Test for {@link MetadataResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
public class MetadataResponseTest {
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
    public void jsonRoundtrip() {
        try {
            MetadataResponse res = new ObjectMapper().readValue(META_JSON, MetadataResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            assertThat("Parsed metadata is NULL", res.getMetadata(), is(notNullValue()));
            assertThat("Incorrect created time", res.getMetadata().getCreatedTimeString(), is(V1_TIME));
            assertThat("Parting created time failed", res.getMetadata().getCreatedTime(), is(notNullValue()));
            assertThat("Incorrect current version", res.getMetadata().getCurrentVersion(), is(CURRENT_VERSION));
            assertThat("Incorrect max versions", res.getMetadata().getMaxVersions(), is(MAX_VERSIONS));
            assertThat("Incorrect oldest version", res.getMetadata().getOldestVersion(), is(OLDEST_VERSION));
            assertThat("Incorrect updated time", res.getMetadata().getUpdatedTimeString(), is(V3_TIME));
            assertThat("Parting updated time failed", res.getMetadata().getUpdatedTime(), is(notNullValue()));
            assertThat("Incorrect number of versions", res.getMetadata().getVersions().size(), is(3));
            assertThat("Incorrect version 1 delete time", res.getMetadata().getVersions().get(1).getDeletionTimeString(), is(V2_TIME));
            assertThat("Parsing version delete time failed", res.getMetadata().getVersions().get(1).getDeletionTime(), is(notNullValue()));
            assertThat("Incorrect version 1 destroyed state", res.getMetadata().getVersions().get(1).isDestroyed(), is(true));
            assertThat("Incorrect version 2 created time", res.getMetadata().getVersions().get(2).getCreatedTimeString(), is(V2_TIME));
            assertThat("Parsing version created failed", res.getMetadata().getVersions().get(2).getCreatedTime(), is(notNullValue()));
            assertThat("Incorrect version 3 destroyed state", res.getMetadata().getVersions().get(3).isDestroyed(), is(false));

        } catch (IOException e) {
            fail("MetadataResponse deserialization failed: " + e.getMessage());
        }
    }
}
