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

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link AuthResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
class HealthResponseTest {
    private static final String CLUSTER_ID = "c9abceea-4f46-4dab-a688-5ce55f89e228";
    private static final String CLUSTER_NAME = "vault-cluster-5515c810";
    private static final String VERSION = "0.9.2";
    private static final Long SERVER_TIME_UTC = 1469555798L;
    private static final Boolean STANDBY = false;
    private static final Boolean SEALED = false;
    private static final Boolean INITIALIZED = true;
    private static final Boolean PERF_STANDBY = false;
    private static final String REPL_PERF_MODE = "disabled";
    private static final String REPL_DR_MODE = "disabled";

    private static final String RES_JSON = "{\n" +
            "  \"cluster_id\": \"" + CLUSTER_ID + "\",\n" +
            "  \"cluster_name\": \"" + CLUSTER_NAME + "\",\n" +
            "  \"version\": \"" + VERSION + "\",\n" +
            "  \"server_time_utc\": " + SERVER_TIME_UTC + ",\n" +
            "  \"standby\": " + STANDBY + ",\n" +
            "  \"sealed\": " + SEALED + ",\n" +
            "  \"initialized\": " + INITIALIZED + ",\n" +
            "  \"replication_perf_mode\": \"" + REPL_PERF_MODE + "\",\n" +
            "  \"replication_dr_mode\": \"" + REPL_DR_MODE + "\",\n" +
            "  \"performance_standby\": " + PERF_STANDBY + "\n" +
            "}";

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        HealthResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(RES_JSON, HealthResponse.class),
                "Health deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(CLUSTER_ID, res.getClusterID(), "Incorrect cluster ID");
        assertEquals(CLUSTER_NAME, res.getClusterName(), "Incorrect cluster name");
        assertEquals(VERSION, res.getVersion(), "Incorrect version");
        assertEquals(SERVER_TIME_UTC, res.getServerTimeUTC(), "Incorrect server time");
        assertEquals(STANDBY, res.isStandby(), "Incorrect standby state");
        assertEquals(SEALED, res.isSealed(), "Incorrect seal state");
        assertEquals(INITIALIZED, res.isInitialized(), "Incorrect initialization state");
        assertEquals(PERF_STANDBY, res.isPerformanceStandby(), "Incorrect performance standby state");
        assertEquals(REPL_PERF_MODE, res.getReplicationPerfMode(), "Incorrect replication perf mode");
        assertEquals(REPL_DR_MODE, res.getReplicationDrMode(), "Incorrect replication DR mode");
    }
}
