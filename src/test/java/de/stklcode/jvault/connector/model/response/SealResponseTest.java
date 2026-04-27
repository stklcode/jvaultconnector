/*
 * Copyright 2016-2026 Stefan Kalscheuer
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

import java.time.ZonedDateTime;

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
    private static final String VERSION = "1.15.4";
    private static final String BUILD_DATE = "2023-11-22T20:59:54Z";
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
        "  \"build_date\": \"" + BUILD_DATE + "\",\n" +
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
        "  \"build_date\": \"" + BUILD_DATE + "\",\n" +
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
        return assertDoesNotThrow(
            () -> objectMapper.readValue(RES_UNSEALED, SealResponse.class),
            "Creation of full model instance failed"
        );
    }

    /**
     * Test creation from JSON value as returned by Vault when sealed (JSON example close to Vault documentation).
     */
    @Test
    void jsonSerializationTestSealed() {
        // First test sealed Vault's response.
        SealResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_SEALED, SealResponse.class),
            "SealResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(TYPE, res.type(), "Incorrect seal type");
        assertTrue(res.sealed(), "Incorrect seal status");
        assertTrue(res.initialized(), "Incorrect initialization status");
        assertEquals(THRESHOLD, res.threshold(), "Incorrect threshold");
        assertEquals(SHARES, res.numberOfShares(), "Incorrect number of shares");
        assertEquals(PROGRESS_SEALED, res.progress(), "Incorrect progress");
        assertEquals("", res.nonce(), "Nonce not empty");
        assertEquals(VERSION, res.version(), "Incorrect version");
        assertEquals(ZonedDateTime.parse(BUILD_DATE), res.buildDate(), "Incorrect build date");
        assertEquals(MIGRATION, res.migration(), "Incorrect migration");
        assertEquals(RECOVERY_SEAL, res.recoverySeal(), "Incorrect recovery seal");
        assertEquals(STORAGE_TYPE, res.storageType(), "Incorrect storage type");
        // And the fields, that should not be filled.
        assertNull(res.clusterName(), "Cluster name should not be populated");
        assertNull(res.clusterId(), "Cluster ID should not be populated");


        // Not test unsealed Vault's response.
        res = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_UNSEALED, SealResponse.class),
            "SealResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(TYPE, res.type(), "Incorrect seal type");
        assertFalse(res.sealed(), "Incorrect seal status");
        assertTrue(res.initialized(), "Incorrect initialization status");
        assertEquals(THRESHOLD, res.threshold(), "Incorrect threshold");
        assertEquals(SHARES, res.numberOfShares(), "Incorrect number of shares");
        assertEquals(PROGRESS_UNSEALED, res.progress(), "Incorrect progress");
        assertEquals(NONCE, res.nonce(), "Incorrect nonce");
        assertEquals(VERSION, res.version(), "Incorrect version");
        assertEquals(ZonedDateTime.parse(BUILD_DATE), res.buildDate(), "Incorrect build date");
        assertEquals(CLUSTER_NAME, res.clusterName(), "Incorrect cluster name");
        assertEquals(CLUSTER_ID, res.clusterId(), "Incorrect cluster ID");
        assertEquals(MIGRATION, res.migration(), "Incorrect migration");
        assertEquals(RECOVERY_SEAL, res.recoverySeal(), "Incorrect recovery seal");
        assertEquals(STORAGE_TYPE, res.storageType(), "Incorrect storage type");
    }
}
