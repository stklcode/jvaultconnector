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

package de.stklcode.jvault.connector.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


/**
 * JUnit Test for AppRoleSecret model.
 *
 * @author Stefan Kalscheuer
 * @since 0.5.0
 */
public class AppRoleSecretTest {

    private static final String TEST_ID = "abc123";
    private static final Map<String, Object> TEST_META = new HashMap<>();
    private static final List<String> TEST_CIDR = Arrays.asList("203.0.113.0/24", "198.51.100.0/24");

    static {
        TEST_META.put("foo", "bar");
        TEST_META.put("number", 1337);
    }

    /**
     * Test constructors.
     */
    @Test
    public void constructorTest() {
        /* Empty constructor */
        AppRoleSecret secret = new AppRoleSecret();
        assertThat(secret.getId(), is(nullValue()));
        assertThat(secret.getAccessor(), is(nullValue()));
        assertThat(secret.getMetadata(), is(nullValue()));
        assertThat(secret.getCidrList(), is(nullValue()));
        assertThat(secret.getCidrListString(), is(emptyString()));
        assertThat(secret.getCreationTime(), is(nullValue()));
        assertThat(secret.getExpirationTime(), is(nullValue()));
        assertThat(secret.getLastUpdatedTime(), is(nullValue()));
        assertThat(secret.getNumUses(), is(nullValue()));
        assertThat(secret.getTtl(), is(nullValue()));

        /* Constructor with ID */
        secret = new AppRoleSecret(TEST_ID);
        assertThat(secret.getId(), is(TEST_ID));
        assertThat(secret.getAccessor(), is(nullValue()));
        assertThat(secret.getMetadata(), is(nullValue()));
        assertThat(secret.getCidrList(), is(nullValue()));
        assertThat(secret.getCidrListString(), is(emptyString()));
        assertThat(secret.getCreationTime(), is(nullValue()));
        assertThat(secret.getExpirationTime(), is(nullValue()));
        assertThat(secret.getLastUpdatedTime(), is(nullValue()));
        assertThat(secret.getNumUses(), is(nullValue()));
        assertThat(secret.getTtl(), is(nullValue()));

        /* Constructor with Metadata and CIDR bindings */
        secret = new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
        assertThat(secret.getId(), is(TEST_ID));
        assertThat(secret.getAccessor(), is(nullValue()));
        assertThat(secret.getMetadata(), is(TEST_META));
        assertThat(secret.getCidrList(), is(TEST_CIDR));
        assertThat(secret.getCidrListString(), is(String.join(",", TEST_CIDR)));
        assertThat(secret.getCreationTime(), is(nullValue()));
        assertThat(secret.getExpirationTime(), is(nullValue()));
        assertThat(secret.getLastUpdatedTime(), is(nullValue()));
        assertThat(secret.getNumUses(), is(nullValue()));
        assertThat(secret.getTtl(), is(nullValue()));
    }

    /**
     * Test setter.
     */
    @Test
    public void setterTest() {
        AppRoleSecret secret = new AppRoleSecret(TEST_ID);
        assertThat(secret.getCidrList(), is(nullValue()));
        assertThat(secret.getCidrListString(), is(emptyString()));
        secret.setCidrList(TEST_CIDR);
        assertThat(secret.getCidrList(), is(TEST_CIDR));
        assertThat(secret.getCidrListString(), is(String.join(",", TEST_CIDR)));
        secret.setCidrList(null);
        assertThat(secret.getCidrList(), is(nullValue()));
        assertThat(secret.getCidrListString(), is(emptyString()));
    }

    /**
     * Test JSON (de)serialization.
     */
    @Test
    public void jsonTest() throws NoSuchFieldException, IllegalAccessException {
        ObjectMapper mapper = new ObjectMapper();

        /* A simple roundtrip first. All set fields should be present afterwards. */
        AppRoleSecret secret = new AppRoleSecret(TEST_ID, TEST_META, TEST_CIDR);
        String secretJson = "";
        try {
            secretJson = mapper.writeValueAsString(secret);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            fail("Serialization failed");
        }
        /* CIDR list is comma-separated when used as input, but List otherwise, hence convert string to list */
        secretJson = commaSeparatedToList(secretJson);

        AppRoleSecret secret2;
        try {
            secret2 = mapper.readValue(secretJson, AppRoleSecret.class);
            assertThat(secret.getId(), is(secret2.getId()));
            assertThat(secret.getMetadata(), is(secret2.getMetadata()));
            assertThat(secret.getCidrList(), is(secret2.getCidrList()));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Deserialization failed");
        }

        /* Test fields, that should not be written to JSON */
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
        try {
            secretJson = mapper.writeValueAsString(secret);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            fail("Serialization failed");
        }
        try {
            secret2 = mapper.readValue(commaSeparatedToList(secretJson), AppRoleSecret.class);
            assertThat(secret.getId(), is(secret2.getId()));
            assertThat(secret.getMetadata(), is(secret2.getMetadata()));
            assertThat(secret.getCidrList(), is(secret2.getCidrList()));
            assertThat(secret2.getAccessor(), is(nullValue()));
            assertThat(secret2.getCreationTime(), is(nullValue()));
            assertThat(secret2.getExpirationTime(), is(nullValue()));
            assertThat(secret2.getLastUpdatedTime(), is(nullValue()));
            assertThat(secret2.getNumUses(), is(nullValue()));
            assertThat(secret2.getTtl(), is(nullValue()));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Deserialization failed");
        }

        /* Those fields should be deserialized from JSON though */
        secretJson = "{\"secret_id\":\"abc123\",\"metadata\":{\"number\":1337,\"foo\":\"bar\"}," +
                "\"cidr_list\":[\"203.0.113.0/24\",\"198.51.100.0/24\"],\"secret_id_accessor\":\"TEST_ACCESSOR\"," +
                "\"creation_time\":\"TEST_CREATION\",\"expiration_time\":\"TEST_EXPIRATION\"," +
                "\"last_updated_time\":\"TEST_LASTUPDATE\",\"secret_id_num_uses\":678,\"secret_id_ttl\":12345}";
        try {
            secret2 = mapper.readValue(secretJson, AppRoleSecret.class);
            assertThat(secret2.getAccessor(), is("TEST_ACCESSOR"));
            assertThat(secret2.getCreationTime(), is("TEST_CREATION"));
            assertThat(secret2.getExpirationTime(), is("TEST_EXPIRATION"));
            assertThat(secret2.getLastUpdatedTime(), is("TEST_LASTUPDATE"));
            assertThat(secret2.getNumUses(), is(678));
            assertThat(secret2.getTtl(), is(12345));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Deserialization failed");
        }

    }

    private static void setPrivateField(Object object, String fieldName, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field = object.getClass().getDeclaredField(fieldName);
        boolean accessible = field.isAccessible();
        field.setAccessible(true);
        field.set(object, value);
        field.setAccessible(accessible);
    }

    private static String commaSeparatedToList(String json) {
        return json.replaceAll("\"cidr_list\":\"([^\"]*)\"", "\"cidr_list\":\\[$1\\]")
                .replaceAll("(\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)", "\"$1\"");
    }

}
