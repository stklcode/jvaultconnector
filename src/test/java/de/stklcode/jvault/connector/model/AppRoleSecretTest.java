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

package de.stklcode.jvault.connector.model;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;


/**
 * JUnit Test for AppRoleSecret model.
 *
 * @author Stefan Kalscheuer
 * @since 0.5.0
 */
class AppRoleSecretTest extends AbstractModelTest<AppRoleSecret> {
    private static final String TEST_ID = "abc123";
    private static final Map<String, Object> TEST_META = Map.of(
        "foo", "bar",
        "number", 1337
    );
    private static final List<String> TEST_CIDR = List.of("203.0.113.0/24", "198.51.100.0/24");

    AppRoleSecretTest() {
        super(AppRoleSecret.class);
    }

    @Override
    protected AppRoleSecret createFull() {
        return new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
    }

    /**
     * Test constructors.
     */
    @Test
    void constructorTest() {
        // Empty constructor.
        AppRoleSecret secret = new AppRoleSecret();
        assertNull(secret.id());
        assertNull(secret.accessor());
        assertNull(secret.metadata());
        assertNull(secret.cidrList());
        assertEquals("", secret.cidrListString());
        assertNull(secret.tokenBoundCidrs());
        assertEquals("", secret.tokenBoundCidrsString());
        assertNull(secret.creationTime());
        assertNull(secret.expirationTime());
        assertNull(secret.lastUpdatedTime());
        assertNull(secret.numUses());
        assertNull(secret.ttl());

        // Constructor with ID.
        secret = new AppRoleSecret(TEST_ID);
        assertEquals(TEST_ID, secret.id());
        assertNull(secret.accessor());
        assertNull(secret.metadata());
        assertNull(secret.cidrList());
        assertEquals("", secret.cidrListString());
        assertNull(secret.tokenBoundCidrs());
        assertEquals("", secret.tokenBoundCidrsString());
        assertNull(secret.creationTime());
        assertNull(secret.expirationTime());
        assertNull(secret.lastUpdatedTime());
        assertNull(secret.numUses());
        assertNull(secret.ttl());

        // Constructor with Metadata and CIDR bindings.
        secret = new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
        assertEquals(TEST_ID, secret.id());
        assertNull(secret.accessor());
        assertEquals(TEST_META, secret.metadata());
        assertEquals(TEST_CIDR, secret.cidrList());
        assertEquals(String.join(",", TEST_CIDR), secret.cidrListString());
        assertNull(secret.tokenBoundCidrs());
        assertEquals("", secret.tokenBoundCidrsString());
        assertNull(secret.creationTime());
        assertNull(secret.expirationTime());
        assertNull(secret.lastUpdatedTime());
        assertNull(secret.numUses());
        assertNull(secret.ttl());
    }

    /**
     * Test JSON (de)serialization.
     */
    @Test
    void jsonTest() {
        // A simple roundtrip first. All set fields should be present afterward.
        AppRoleSecret secret = new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
        String secretJson = assertDoesNotThrow(() -> objectMapper.writeValueAsString(secret), "Serialization failed");
        // CIDR list is comma-separated when used as input, but List otherwise, hence convert string to list.
        String secretJson2 = commaSeparatedToList(secretJson);

        AppRoleSecret secret2 = assertDoesNotThrow(
            () -> objectMapper.readValue(secretJson2, AppRoleSecret.class),
            "Deserialization failed"
        );
        assertEquals(secret2.id(), secret.id());
        assertEquals(secret2.metadata(), secret.metadata());
        assertEquals(secret2.cidrList(), secret.cidrList());

        // Test fields, that should not be written to JSON.
        var secret3 = new AppRoleSecret(TEST_ID, "TEST_ACCESSOR", TEST_META, TEST_CIDR, null, "TEST_CREATION", "TEST_EXPIRATION", "TEST_LASTUPDATE", 678, 12345);
        String secretJson3 = assertDoesNotThrow(() -> objectMapper.writeValueAsString(secret3), "Serialization failed");
        secret2 = assertDoesNotThrow(
            () -> objectMapper.readValue(commaSeparatedToList(secretJson3), AppRoleSecret.class),
            "Deserialization failed"
        );
        assertEquals(secret2.id(), secret.id());
        assertEquals(secret2.metadata(), secret.metadata());
        assertEquals(secret2.cidrList(), secret.cidrList());
        assertNull(secret2.accessor());
        assertNull(secret2.creationTime());
        assertNull(secret2.expirationTime());
        assertNull(secret2.lastUpdatedTime());
        assertNull(secret2.numUses());
        assertNull(secret2.ttl());

        // Those fields should be deserialized from JSON though.
        String secretJson4 = "{\"secret_id\":\"abc123\",\"metadata\":{\"number\":1337,\"foo\":\"bar\"}," +
            "\"cidr_list\":[\"203.0.113.0/24\",\"198.51.100.0/24\"],\"cidr_list\":[\"192.0.2.0/24\",\"198.51.100.0/24\"]," +
            "\"secret_id_accessor\":\"TEST_ACCESSOR\"," +
            "\"creation_time\":\"TEST_CREATION\",\"expiration_time\":\"TEST_EXPIRATION\"," +
            "\"last_updated_time\":\"TEST_LASTUPDATE\",\"secret_id_num_uses\":678,\"secret_id_ttl\":12345}";
        secret2 = assertDoesNotThrow(() -> objectMapper.readValue(secretJson4, AppRoleSecret.class), "Deserialization failed");
        assertEquals("TEST_ACCESSOR", secret2.accessor());
        assertEquals("TEST_CREATION", secret2.creationTime());
        assertEquals("TEST_EXPIRATION", secret2.expirationTime());
        assertEquals("TEST_LASTUPDATE", secret2.lastUpdatedTime());
        assertEquals(678, secret2.numUses());
        assertEquals(12345, secret2.ttl());
    }

    private static String commaSeparatedToList(String json) {
        return json.replaceAll("\"cidr_list\":\"([^\"]*)\"", "\"cidr_list\":[$1]")
            .replaceAll("\"token_bound_cidrs\":\"([^\"]*)\"", "\"token_bound_cidrs\":[$1]")
            .replaceAll("(\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)", "\"$1\"");
    }
}
