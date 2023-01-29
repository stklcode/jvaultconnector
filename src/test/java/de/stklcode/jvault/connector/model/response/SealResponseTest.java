/*
 * Copyright 2016-2023 Stefan Kalscheuer
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
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link SealResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
class SealResponseTest extends AbstractModelTest<SealResponse> {
    private static final String TYPE = "shamir";
    private static final Integer THRESHOLD = 3;
    private static final Integer SHARES = 5;
    private static final Integer PROGRESS_SEALED = 2;
    private static final Integer PROGRESS_UNSEALED = 0;
    private static final String VERSION = "1.8.2";
    private static final String CLUSTER_NAME = "vault-cluster-d6ec3c7f";
    private static final String CLUSTER_ID = "3e8b3fec-3749-e056-ba41-b62a63b997e8";
    private static final String NONCE = "ef05d55d-4d2c-c594-a5e8-55bc88604c24";
    private static final Boolean MIGRATION = false;
    private static final Boolean RECOVERY_SEAL = false;
    private static final String STORAGE_TYPE = "file";

    private static final String RES_SEALED = "{\n" +
            "  \"type\": \"" + TYPE + "\",\n" +
            "  \"sealed\": true,\n" +
            "  \"initialized\": true,\n" +
            "  \"t\": " + THRESHOLD + ",\n" +
            "  \"n\": " + SHARES + ",\n" +
            "  \"progress\": " + PROGRESS_SEALED + ",\n" +
            "  \"nonce\": \"\",\n" +
            "  \"version\": \"" + VERSION + "\",\n" +
            "  \"migration\": \"" + MIGRATION + "\",\n" +
            "  \"recovery_seal\": \"" + RECOVERY_SEAL + "\",\n" +
            "  \"storage_type\": \"" + STORAGE_TYPE + "\"\n" +
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
            "  \"nonce\": \"" + NONCE + "\",\n" +
            "  \"migration\": \"" + MIGRATION + "\",\n" +
            "  \"recovery_seal\": \"" + RECOVERY_SEAL + "\",\n" +
            "  \"storage_type\": \"" + STORAGE_TYPE + "\"\n" +
            "}";

    SealResponseTest() {
        super(SealResponse.class);
    }

    @Override
    protected SealResponse createFull() {
        try {
            return new ObjectMapper().readValue(RES_UNSEALED, SealResponse.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    /**
     * Test creation from JSON value as returned by Vault when sealed (JSON example close to Vault documentation).
     */
    @Test
    void jsonRoundtripSealed() {
        // First test sealed Vault's response.
        SealResponse res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(RES_SEALED, SealResponse.class),
                "SealResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(TYPE, res.getType(), "Incorrect seal type");
        assertTrue(res.isSealed(), "Incorrect seal status");
        assertTrue(res.isInitialized(), "Incorrect initialization status");
        assertEquals(THRESHOLD, res.getThreshold(), "Incorrect threshold");
        assertEquals(SHARES, res.getNumberOfShares(), "Incorrect number of shares");
        assertEquals(PROGRESS_SEALED, res.getProgress(), "Incorrect progress");
        assertEquals("", res.getNonce(), "Nonce not empty");
        assertEquals(VERSION, res.getVersion(), "Incorrect version");
        assertEquals(MIGRATION, res.getMigration(), "Incorrect migration");
        assertEquals(RECOVERY_SEAL, res.getRecoverySeal(), "Incorrect recovery seal");
        assertEquals(STORAGE_TYPE, res.getStorageType(), "Incorrect storage type");
        // And the fields, that should not be filled.
        assertNull(res.getClusterName(), "Cluster name should not be populated");
        assertNull(res.getClusterId(), "Cluster ID should not be populated");


        // Not test unsealed Vault's response.
        res = assertDoesNotThrow(
                () -> new ObjectMapper().readValue(RES_UNSEALED, SealResponse.class),
                "SealResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(TYPE, res.getType(), "Incorrect seal type");
        assertFalse(res.isSealed(), "Incorrect seal status");
        assertTrue(res.isInitialized(), "Incorrect initialization status");
        assertEquals(THRESHOLD, res.getThreshold(), "Incorrect threshold");
        assertEquals(SHARES, res.getNumberOfShares(), "Incorrect number of shares");
        assertEquals(PROGRESS_UNSEALED, res.getProgress(), "Incorrect progress");
        assertEquals(NONCE, res.getNonce(), "Incorrect nonce");
        assertEquals(VERSION, res.getVersion(), "Incorrect version");
        assertEquals(CLUSTER_NAME, res.getClusterName(), "Incorrect cluster name");
        assertEquals(CLUSTER_ID, res.getClusterId(), "Incorrect cluster ID");
        assertEquals(MIGRATION, res.getMigration(), "Incorrect migration");
        assertEquals(RECOVERY_SEAL, res.getRecoverySeal(), "Incorrect recovery seal");
        assertEquals(STORAGE_TYPE, res.getStorageType(), "Incorrect storage type");
    }
}
