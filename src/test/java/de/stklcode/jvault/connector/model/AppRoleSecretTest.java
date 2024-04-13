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

package de.stklcode.jvault.connector.model;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


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
        assertNull(secret.getId());
        assertNull(secret.getAccessor());
        assertNull(secret.getMetadata());
        assertNull(secret.getCidrList());
        assertEquals("", secret.getCidrListString());
        assertNull(secret.getCreationTime());
        assertNull(secret.getExpirationTime());
        assertNull(secret.getLastUpdatedTime());
        assertNull(secret.getNumUses());
        assertNull(secret.getTtl());

        // Constructor with ID.
        secret = new AppRoleSecret(TEST_ID);
        assertEquals(TEST_ID, secret.getId());
        assertNull(secret.getAccessor());
        assertNull(secret.getMetadata());
        assertNull(secret.getCidrList());
        assertEquals("", secret.getCidrListString());
        assertNull(secret.getCreationTime());
        assertNull(secret.getExpirationTime());
        assertNull(secret.getLastUpdatedTime());
        assertNull(secret.getNumUses());
        assertNull(secret.getTtl());

        // Constructor with Metadata and CIDR bindings.
        secret = new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
        assertEquals(TEST_ID, secret.getId());
        assertNull(secret.getAccessor());
        assertEquals(TEST_META, secret.getMetadata());
        assertEquals(TEST_CIDR, secret.getCidrList());
        assertEquals(String.join(",", TEST_CIDR), secret.getCidrListString());
        assertNull(secret.getCreationTime());
        assertNull(secret.getExpirationTime());
        assertNull(secret.getLastUpdatedTime());
        assertNull(secret.getNumUses());
        assertNull(secret.getTtl());
    }

    /**
     * Test setter.
     */
    @Test
    void setterTest() {
        AppRoleSecret secret = new AppRoleSecret(TEST_ID);
        assertNull(secret.getCidrList());
        assertEquals("", secret.getCidrListString());
        secret.setCidrList(TEST_CIDR);
        assertEquals(TEST_CIDR, secret.getCidrList());
        assertEquals(String.join(",", TEST_CIDR), secret.getCidrListString());
        secret.setCidrList(null);
        assertNull(secret.getCidrList());
        assertEquals("", secret.getCidrListString());
    }

    /**
     * Test JSON (de)serialization.
     */
    @Test
    void jsonTest() throws NoSuchFieldException, IllegalAccessException {
        // A simple roundtrip first. All set fields should be present afterward.
        AppRoleSecret secret = new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
        String secretJson = assertDoesNotThrow(() -> objectMapper.writeValueAsString(secret), "Serialization failed");
        // CIDR list is comma-separated when used as input, but List otherwise, hence convert string to list.
        String secretJson2 = commaSeparatedToList(secretJson);

        AppRoleSecret secret2 = assertDoesNotThrow(
                () -> objectMapper.readValue(secretJson2, AppRoleSecret.class),
                "Deserialization failed"
        );
        assertEquals(secret2.getId(), secret.getId());
        assertEquals(secret2.getMetadata(), secret.getMetadata());
        assertEquals(secret2.getCidrList(), secret.getCidrList());

        // Test fields, that should not be written to JSON.
        setPrivateField(secret, "accessor", "TEST_ACCESSOR");
        assumeTrue("TEST_ACCESSOR".equals(secret.getAccessor()));
        setPrivateField(secret, "creationTime", "TEST_CREATION");
        assumeTrue("TEST_CREATION".equals(secret.getCreationTime()));
        setPrivateField(secret, "expirationTime", "TEST_EXPIRATION");
        assumeTrue("TEST_EXPIRATION".equals(secret.getExpirationTime()));
        setPrivateField(secret, "lastUpdatedTime", "TEST_UPDATETIME");
        assumeTrue("TEST_UPDATETIME".equals(secret.getLastUpdatedTime()));
        setPrivateField(secret, "numUses", 678);
        assumeTrue(secret.getNumUses() == 678);
        setPrivateField(secret, "ttl", 12345);
        assumeTrue(secret.getTtl() == 12345);
        String secretJson3 = assertDoesNotThrow(() -> objectMapper.writeValueAsString(secret), "Serialization failed");
        secret2 = assertDoesNotThrow(
                () -> objectMapper.readValue(commaSeparatedToList(secretJson3), AppRoleSecret.class),
                "Deserialization failed"
        );
        assertEquals(secret2.getId(), secret.getId());
        assertEquals(secret2.getMetadata(), secret.getMetadata());
        assertEquals(secret2.getCidrList(), secret.getCidrList());
        assertNull(secret2.getAccessor());
        assertNull(secret2.getCreationTime());
        assertNull(secret2.getExpirationTime());
        assertNull(secret2.getLastUpdatedTime());
        assertNull(secret2.getNumUses());
        assertNull(secret2.getTtl());

        // Those fields should be deserialized from JSON though.
        String secretJson4 = "{\"secret_id\":\"abc123\",\"metadata\":{\"number\":1337,\"foo\":\"bar\"}," +
                "\"cidr_list\":[\"203.0.113.0/24\",\"198.51.100.0/24\"],\"secret_id_accessor\":\"TEST_ACCESSOR\"," +
                "\"creation_time\":\"TEST_CREATION\",\"expiration_time\":\"TEST_EXPIRATION\"," +
                "\"last_updated_time\":\"TEST_LASTUPDATE\",\"secret_id_num_uses\":678,\"secret_id_ttl\":12345}";
        secret2 = assertDoesNotThrow(() -> objectMapper.readValue(secretJson4, AppRoleSecret.class), "Deserialization failed");
        assertEquals("TEST_ACCESSOR", secret2.getAccessor());
        assertEquals("TEST_CREATION", secret2.getCreationTime());
        assertEquals("TEST_EXPIRATION", secret2.getExpirationTime());
        assertEquals("TEST_LASTUPDATE", secret2.getLastUpdatedTime());
        assertEquals(678, secret2.getNumUses());
        assertEquals(12345, secret2.getTtl());
    }

    private static void setPrivateField(Object object, String fieldName, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field = object.getClass().getDeclaredField(fieldName);
        boolean accessible = field.canAccess(object);
        field.setAccessible(true);
        field.set(object, value);
        field.setAccessible(accessible);
    }

    private static String commaSeparatedToList(String json) {
        return json.replaceAll("\"cidr_list\":\"([^\"]*)\"", "\"cidr_list\":[$1]")
                .replaceAll("(\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)", "\"$1\"");
    }
}
