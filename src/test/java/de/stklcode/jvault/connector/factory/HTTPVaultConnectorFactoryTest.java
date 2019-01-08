/*
 * Copyright 2016-2019 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.factory;

import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.exception.TlsException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import org.junit.Rule;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.migrationsupport.rules.EnableRuleMigrationSupport;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.NoSuchFileException;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * JUnit test for HTTP Vault connector factory
 *
 * @author Stefan Kalscheuer
 * @since 0.6.0
 */
@EnableRuleMigrationSupport
public class HTTPVaultConnectorFactoryTest {
    private static String VAULT_ADDR = "https://localhost:8201";
    private static Integer VAULT_MAX_RETRIES = 13;
    private static String VAULT_TOKEN = "00001111-2222-3333-4444-555566667777";

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder();

    @Rule
    public final EnvironmentVariables environment = new EnvironmentVariables();

    /**
     * Test building from environment variables
     */
    @Test
    public void testFromEnv() throws NoSuchFieldException, IllegalAccessException, IOException {
        /* Provide address only should be enough */
        setenv(VAULT_ADDR, null, null, null);

        HTTPVaultConnectorFactory factory = null;
        HTTPVaultConnector connector;
        try {
            factory = VaultConnectorFactory.httpFactory().fromEnv();
        } catch (VaultConnectorException e) {
            fail("Factory creation from minimal environment failed");
        }
        connector = factory.build();

        assertThat("URL nor set correctly", getPrivate(connector, "baseURL"), is(equalTo(VAULT_ADDR + "/v1/")));
        assertThat("Trusted CA cert set when no cert provided", getPrivate(connector, "trustedCaCert"), is(nullValue()));
        assertThat("Non-default number of retries, when none set", getPrivate(connector, "retries"), is(0));

        /* Provide address and number of retries */
        setenv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), null);

        try {
            factory = VaultConnectorFactory.httpFactory().fromEnv();
        } catch (VaultConnectorException e) {
            fail("Factory creation from environment failed");
        }
        connector = factory.build();

        assertThat("URL nor set correctly", getPrivate(connector, "baseURL"), is(equalTo(VAULT_ADDR + "/v1/")));
        assertThat("Trusted CA cert set when no cert provided", getPrivate(connector, "trustedCaCert"), is(nullValue()));
        assertThat("Number of retries not set correctly", getPrivate(connector, "retries"), is(VAULT_MAX_RETRIES));

        /* Provide CA certificate */
        String VAULT_CACERT = tmpDir.newFolder().toString() + "/doesnotexist";
        setenv(VAULT_ADDR, VAULT_CACERT, VAULT_MAX_RETRIES.toString(), null);

        try {
            VaultConnectorFactory.httpFactory().fromEnv();
            fail("Creation with unknown cert path failed.");
        } catch (VaultConnectorException e) {
            assertThat(e, is(instanceOf(TlsException.class)));
            assertThat(e.getCause(), is(instanceOf(NoSuchFileException.class)));
            assertThat(((NoSuchFileException)e.getCause()).getFile(), is(VAULT_CACERT));
        }

        /* Automatic authentication */
        setenv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), VAULT_TOKEN);

        try {
            factory = VaultConnectorFactory.httpFactory().fromEnv();
        } catch (VaultConnectorException e) {
            fail("Factory creation from minimal environment failed");
        }
        assertThat("Token nor set correctly", getPrivate(getPrivate(factory, "delegate"), "token"), is(equalTo(VAULT_TOKEN)));
    }

    private void setenv(String vault_addr, String vault_cacert, String vault_max_retries, String vault_token) {
        environment.set("VAULT_ADDR", vault_addr);
        environment.set("VAULT_CACERT", vault_cacert);
        environment.set("VAULT_MAX_RETRIES", vault_max_retries);
        environment.set("VAULT_TOKEN", vault_token);
    }

    private Object getPrivate(Object target, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = target.getClass().getDeclaredField(fieldName);
        if (field.isAccessible())
            return field.get(target);
        field.setAccessible(true);
        Object value = field.get(target);
        field.setAccessible(false);
        return value;
    }
}
