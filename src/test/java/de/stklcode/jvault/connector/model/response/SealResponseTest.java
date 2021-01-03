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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit Test for {@link SealResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
public class SealResponseTest {
    private static final String TYPE = "shamir";
    private static final Integer THRESHOLD = 3;
    private static final Integer SHARES = 5;
    private static final Integer PROGRESS_SEALED = 2;
    private static final Integer PROGRESS_UNSEALED = 0;
    private static final String VERSION = "0.11.2";
    private static final String CLUSTER_NAME = "vault-cluster-d6ec3c7f";
    private static final String CLUSTER_ID = "3e8b3fec-3749-e056-ba41-b62a63b997e8";
    private static final String NONCE = "ef05d55d-4d2c-c594-a5e8-55bc88604c24";

    private static final String RES_SEALED = "{\n" +
            "  \"type\": \"" + TYPE + "\",\n" +
            "  \"sealed\": true,\n" +
            "  \"initialized\": true,\n" +
            "  \"t\": " + THRESHOLD + ",\n" +
            "  \"n\": " + SHARES + ",\n" +
            "  \"progress\": " + PROGRESS_SEALED + ",\n" +
            "  \"nonce\": \"\",\n" +
            "  \"version\": \"" + VERSION + "\"\n" +
            "}";

    private static final String RES_UNSEALED = "{\n" +
            "  \"type\": \"" + TYPE + "\",\n" +
            "  \"sealed\": false,\n" +
            "  \"initialized\": true,\n" +
            "  \"t\": " + THRESHOLD + ",\n" +
            "  \"n\": " + SHARES + ",\n" +
            "  \"progress\": " + PROGRESS_UNSEALED + ",\n" +
            "  \"version\": \"" + VERSION + "\",\n" +
            "  \"cluster_name\": \"" + CLUSTER_NAME + "\",\n" +
            "  \"cluster_id\": \"" + CLUSTER_ID + "\",\n" +
            "  \"nonce\": \"" + NONCE + "\"\n" +
            "}";

    /**
     * Test creation from JSON value as returned by Vault when sealed (JSON example close to Vault documentation).
     */
    @Test
    public void jsonRoundtripSealed() {
        // First test sealed Vault's response.
        try {
            SealResponse res = new ObjectMapper().readValue(RES_SEALED, SealResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            assertThat("Incorrect seal type", res.getType(), is(TYPE));
            assertThat("Incorrect seal status", res.isSealed(), is(true));
            assertThat("Incorrect initialization status", res.isInitialized(), is(true));
            assertThat("Incorrect threshold", res.getThreshold(), is(THRESHOLD));
            assertThat("Incorrect number of shares", res.getNumberOfShares(), is(SHARES));
            assertThat("Incorrect progress", res.getProgress(), is(PROGRESS_SEALED));
            assertThat("Nonce not empty", res.getNonce(), is(""));
            assertThat("Incorrect version", res.getVersion(), is(VERSION));
            // And the fields, that should not be filled.
            assertThat("Cluster name should not be populated", res.getClusterName(), is(nullValue()));
            assertThat("Cluster ID should not be populated", res.getClusterId(), is(nullValue()));
        } catch (IOException e) {
            fail("TokenResponse deserialization failed: " + e.getMessage());
        }


        // Not test unsealed Vault's response.
        try {
            SealResponse res = new ObjectMapper().readValue(RES_UNSEALED, SealResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            assertThat("Incorrect seal type", res.getType(), is(TYPE));
            assertThat("Incorrect seal status", res.isSealed(), is(false));
            assertThat("Incorrect initialization status", res.isInitialized(), is(true));
            assertThat("Incorrect threshold", res.getThreshold(), is(THRESHOLD));
            assertThat("Incorrect number of shares", res.getNumberOfShares(), is(SHARES));
            assertThat("Incorrect progress", res.getProgress(), is(PROGRESS_UNSEALED));
            assertThat("Incorrect nonce", res.getNonce(), is(NONCE));
            assertThat("Incorrect version", res.getVersion(), is(VERSION));
            assertThat("Incorrect cluster name", res.getClusterName(), is(CLUSTER_NAME));
            assertThat("Incorrect cluster ID", res.getClusterId(), is(CLUSTER_ID));
        } catch (IOException e) {
            fail("TokenResponse deserialization failed: " + e.getMessage());
        }
    }
}
