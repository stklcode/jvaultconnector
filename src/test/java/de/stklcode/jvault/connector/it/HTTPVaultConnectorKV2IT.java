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

package de.stklcode.jvault.connector.it;

import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.MetadataResponse;
import de.stklcode.jvault.connector.model.response.SecretResponse;
import de.stklcode.jvault.connector.model.response.SecretVersionResponse;
import org.junit.jupiter.api.*;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singletonMap;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for HTTP Vault connector KV v2 module.
 */
@DisplayName("KV v2 Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HTTPVaultConnectorKV2IT extends HTTPVaultConnectorITBase {
    private static final String MOUNT_KV2 = "kv";
    private static final String SECRET2_KEY = "foo2";
    private static final String SECRET2_VALUE1 = "bar2";
    private static final String SECRET2_VALUE2 = "bar3";
    private static final String SECRET2_VALUE3 = "bar4";
    private static final String SECRET2_VALUE4 = "bar4";

    /**
     * Test reading of secrets from KV v2 store.
     */
    @Test
    @Order(10)
    @DisplayName("Read v2 secret")
    void readSecretTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        // Try to read accessible path with known value.
        SecretResponse res = assertDoesNotThrow(
            () -> connector.kv2().readData(MOUNT_KV2, SECRET2_KEY),
            "Valid secret path could not be read"
        );
        assertNotNull(res.metadata(), "Metadata not populated for KV v2 secret");
        assertEquals(2, res.metadata().version(), "Unexpected secret version");
        assertEquals(SECRET2_VALUE2, res.get("value"), "Known secret returned invalid value");

        // Try to read different version of same secret.
        res = assertDoesNotThrow(
            () -> connector.kv2().readVersion(MOUNT_KV2, SECRET2_KEY, 1),
            "Valid secret version could not be read"
        );
        assertEquals(1, res.metadata().version(), "Unexpected secret version");
        assertEquals(SECRET2_VALUE1, res.get("value"), "Known secret returned invalid value");
    }

    /**
     * Test writing of secrets to KV v2 store.
     */
    @Test
    @Order(20)
    @DisplayName("Write v2 secret")
    void writeSecretTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        // First get the current version of the secret.
        MetadataResponse res = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading secret metadata failed"
        );
        int currentVersion = res.metadata().currentVersion();

        // Now write (update) the data and verify the version.
        Map<String, Object> data = new HashMap<>();
        data.put("value", SECRET2_VALUE3);
        SecretVersionResponse res2 = assertDoesNotThrow(
            () -> connector.kv2().writeData(MOUNT_KV2, SECRET2_KEY, data),
            "Writing secret to KV v2 store failed"
        );
        assertEquals(currentVersion + 1, res2.metadata().version(), "Version not updated after writing secret");
        int currentVersion2 = res2.metadata().version();

        // Verify the content.
        SecretResponse res3 = assertDoesNotThrow(
            () -> connector.kv2().readData(MOUNT_KV2, SECRET2_KEY),
            "Reading secret from KV v2 store failed"
        );
        assertEquals(SECRET2_VALUE3, res3.get("value"), "Data not updated correctly");

        // Now try with explicit CAS value (invalid).
        Map<String, Object> data4 = singletonMap("value", SECRET2_VALUE4);
        assertThrows(
            InvalidResponseException.class,
            () -> connector.kv2().writeData(MOUNT_KV2, SECRET2_KEY, data4, currentVersion2 - 1),
            "Writing secret to KV v2 with invalid CAS value succeeded"
        );

        // And finally with a correct CAS value.
        Map<String, Object> data5 = singletonMap("value", SECRET2_VALUE4);
        assertDoesNotThrow(() -> connector.kv2().writeData(MOUNT_KV2, SECRET2_KEY, data5, currentVersion2));
    }

    /**
     * Test reading of secret metadata from KV v2 store.
     */
    @Test
    @Order(30)
    @DisplayName("Read v2 metadata")
    void readSecretMetadataTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        // Read current metadata first.
        MetadataResponse res = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading secret metadata failed"
        );
        Integer maxVersions = res.metadata().maxVersions();
        assumeTrue(10 == res.metadata().maxVersions(), "Unexpected maximum number of versions");

        // Now update the metadata.
        assertDoesNotThrow(
            () -> connector.kv2().updateMetadata(MOUNT_KV2, SECRET2_KEY, maxVersions + 1, true),
            "Updating secret metadata failed"
        );

        // And verify the result.
        res = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading secret metadata failed"
        );
        assertEquals(maxVersions + 1, res.metadata().maxVersions(), "Unexpected maximum number of versions");
    }

    /**
     * Test updating secret metadata in KV v2 store.
     */
    @Test
    @Order(40)
    @DisplayName("Update v2 metadata")
    void updateSecretMetadataTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        // Try to read accessible path with known value.
        MetadataResponse res = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Valid secret path could not be read"
        );
        assertNotNull(res.metadata(), "Metadata not populated for KV v2 secret");
        assertEquals(4, res.metadata().currentVersion(), "Unexpected secret version");
        assertEquals(4, res.metadata().versions().size(), "Unexpected number of secret versions");
        assertNotNull(res.metadata().createdTime(), "Creation date should be present");
        assertNotNull(res.metadata().updatedTime(), "Update date should be present");
        assertEquals(11, res.metadata().maxVersions(), "Unexpected maximum number of versions");
    }

    /**
     * Test deleting specific secret versions from KV v2 store.
     */
    @Test
    @Order(50)
    @DisplayName("Version handling")
    void handleSecretVersionsTest() {
        authUser();
        assumeTrue(connector.isAuthorized());

        // Try to delete non-existing versions.
        assertDoesNotThrow(
            () -> connector.kv2().deleteVersions(MOUNT_KV2, SECRET2_KEY, 5, 42),
            "Revealed non-existence of secret versions"
        );
        assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Revealed non-existence of secret versions"
        );

        // Now delete existing version and verify.
        assertDoesNotThrow(
            () -> connector.kv2().deleteVersions(MOUNT_KV2, SECRET2_KEY, 1),
            "Deleting existing version failed"
        );
        MetadataResponse meta = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading deleted secret metadata failed"
        );
        assertNotNull(
            meta.metadata().versions().get(1).deletionTime(),
            "Expected deletion time for secret 1"
        );

        // Undelete the just deleted version.
        assertDoesNotThrow(
            () -> connector.kv2().undeleteVersions(MOUNT_KV2, SECRET2_KEY, 1),
            "Undeleting existing version failed"
        );
        meta = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading deleted secret metadata failed"
        );
        assertNull(
            meta.metadata().versions().get(1).deletionTime(),
            "Expected deletion time for secret 1 to be reset"
        );

        // Now destroy it.
        assertDoesNotThrow(
            () -> connector.kv2().destroyVersions(MOUNT_KV2, SECRET2_KEY, 1),
            "Destroying existing version failed"
        );
        meta = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading destroyed secret metadata failed"
        );
        assertTrue(
            meta.metadata().versions().get(1).destroyed(),
            "Expected secret 1 to be marked destroyed"
        );

        // Delete latest version.
        assertDoesNotThrow(
            () -> connector.kv2().deleteLatestVersion(MOUNT_KV2, SECRET2_KEY),
            "Deleting latest version failed"
        );
        meta = assertDoesNotThrow(
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading deleted secret metadata failed"
        );
        assertNotNull(
            meta.metadata().versions().get(4).deletionTime(),
            "Expected secret version 4 to be deleted"
        );

        // Delete all versions.
        assertDoesNotThrow(
            () -> connector.kv2().deleteAllVersions(MOUNT_KV2, SECRET2_KEY),
            "Deleting latest version failed"
        );
        assertThrows(
            InvalidResponseException.class,
            () -> connector.kv2().readMetadata(MOUNT_KV2, SECRET2_KEY),
            "Reading metadata of deleted secret should not succeed"
        );
    }
}
