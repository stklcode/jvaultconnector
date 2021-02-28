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

package de.stklcode.jvault.connector.factory;

import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.exception.TlsException;
import de.stklcode.jvault.connector.test.EnvironmentMock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.NoSuchFileException;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JUnit test for HTTP Vault connector factory
 *
 * @author Stefan Kalscheuer
 * @since 0.6.0
 */
class HTTPVaultConnectorFactoryTest {
    private static String VAULT_ADDR = "https://localhost:8201";
    private static Integer VAULT_MAX_RETRIES = 13;
    private static String VAULT_TOKEN = "00001111-2222-3333-4444-555566667777";

    @TempDir
    File tempDir;

    /**
     * Test building from environment variables
     */
    @Test
    void testFromEnv() throws NoSuchFieldException, IllegalAccessException, IOException {
        /* Provide address only should be enough */
        setenv(VAULT_ADDR, null, null, null);

        HTTPVaultConnectorFactory factory = assertDoesNotThrow(
                () -> VaultConnectorFactory.httpFactory().fromEnv(),
                "Factory creation from minimal environment failed"
        );
        HTTPVaultConnector connector = factory.build();

        assertThat("URL nor set correctly", getRequestHelperPrivate(connector, "baseURL"), is(equalTo(VAULT_ADDR + "/v1/")));
        assertThat("Trusted CA cert set when no cert provided", getRequestHelperPrivate(connector, "trustedCaCert"), is(nullValue()));
        assertThat("Non-default number of retries, when none set", getRequestHelperPrivate(connector, "retries"), is(0));

        /* Provide address and number of retries */
        setenv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), null);

        factory = assertDoesNotThrow(
                () -> VaultConnectorFactory.httpFactory().fromEnv(),
                "Factory creation from environment failed"
        );
        connector = factory.build();

        assertThat("URL nor set correctly", getRequestHelperPrivate(connector, "baseURL"), is(equalTo(VAULT_ADDR + "/v1/")));
        assertThat("Trusted CA cert set when no cert provided", getRequestHelperPrivate(connector, "trustedCaCert"), is(nullValue()));
        assertThat("Number of retries not set correctly", getRequestHelperPrivate(connector, "retries"), is(VAULT_MAX_RETRIES));

        /* Provide CA certificate */
        String VAULT_CACERT = tempDir.toString() + "/doesnotexist";
        setenv(VAULT_ADDR, VAULT_CACERT, VAULT_MAX_RETRIES.toString(), null);

        TlsException e = assertThrows(
                TlsException.class,
                () -> VaultConnectorFactory.httpFactory().fromEnv(),
                "Creation with unknown cert path failed."
        );
        assertThat(e.getCause(), is(instanceOf(NoSuchFileException.class)));
        assertThat(((NoSuchFileException) e.getCause()).getFile(), is(VAULT_CACERT));

        /* Automatic authentication */
        setenv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), VAULT_TOKEN);

        factory = assertDoesNotThrow(
                () -> VaultConnectorFactory.httpFactory().fromEnv(),
                "Factory creation from minimal environment failed"
        );
        assertThat("Token nor set correctly", getPrivate(getPrivate(factory, "delegate"), "token"), is(equalTo(VAULT_TOKEN)));
    }

    private void setenv(String vault_addr, String vault_cacert, String vault_max_retries, String vault_token) {
        EnvironmentMock.setenv("VAULT_ADDR", vault_addr);
        EnvironmentMock.setenv("VAULT_CACERT", vault_cacert);
        EnvironmentMock.setenv("VAULT_MAX_RETRIES", vault_max_retries);
        EnvironmentMock.setenv("VAULT_TOKEN", vault_token);
    }

    private Object getRequestHelperPrivate(HTTPVaultConnector connector, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        return getPrivate(getPrivate(connector, "request"), fieldName);
    }

    private Object getPrivate(Object target, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = target.getClass().getDeclaredField(fieldName);
        if (field.isAccessible()) {
            return field.get(target);
        }
        field.setAccessible(true);
        Object value = field.get(target);
        field.setAccessible(false);
        return value;
    }
}
