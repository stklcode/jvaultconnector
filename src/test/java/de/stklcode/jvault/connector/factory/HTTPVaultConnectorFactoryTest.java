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

import com.github.stefanbirkner.systemlambda.SystemLambda;
import de.stklcode.jvault.connector.HTTPVaultConnector;
import de.stklcode.jvault.connector.exception.TlsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.NoSuchFileException;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
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
    void testFromEnv() throws Exception {
        /* Provide address only should be enough */
        withVaultEnv(VAULT_ADDR, null, null, null).execute(() -> {
            HTTPVaultConnectorFactory factory = assertDoesNotThrow(
                    () -> VaultConnectorFactory.httpFactory().fromEnv(),
                    "Factory creation from minimal environment failed"
            );
            HTTPVaultConnector connector = factory.build();

            assertThat("URL nor set correctly", getRequestHelperPrivate(connector, "baseURL"), is(equalTo(VAULT_ADDR + "/v1/")));
            assertThat("Trusted CA cert set when no cert provided", getRequestHelperPrivate(connector, "trustedCaCert"), is(nullValue()));
            assertThat("Non-default number of retries, when none set", getRequestHelperPrivate(connector, "retries"), is(0));

            return null;
        });

        /* Provide address and number of retries */
        withVaultEnv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), null).execute(() -> {
            HTTPVaultConnectorFactory factory = assertDoesNotThrow(
                    () -> VaultConnectorFactory.httpFactory().fromEnv(),
                    "Factory creation from environment failed"
            );
            HTTPVaultConnector connector = factory.build();

            assertThat("URL nor set correctly", getRequestHelperPrivate(connector, "baseURL"), is(equalTo(VAULT_ADDR + "/v1/")));
            assertThat("Trusted CA cert set when no cert provided", getRequestHelperPrivate(connector, "trustedCaCert"), is(nullValue()));
            assertThat("Number of retries not set correctly", getRequestHelperPrivate(connector, "retries"), is(VAULT_MAX_RETRIES));

            return null;
        });

        /* Provide CA certificate */
        String VAULT_CACERT = tempDir.toString() + "/doesnotexist";
        withVaultEnv(VAULT_ADDR, VAULT_CACERT, VAULT_MAX_RETRIES.toString(), null).execute(() -> {
            TlsException e = assertThrows(
                    TlsException.class,
                    () -> VaultConnectorFactory.httpFactory().fromEnv(),
                    "Creation with unknown cert path failed."
            );
            assertThat(e.getCause(), is(instanceOf(NoSuchFileException.class)));
            assertThat(((NoSuchFileException) e.getCause()).getFile(), is(VAULT_CACERT));

            return null;
        });

        /* Automatic authentication */
        withVaultEnv(VAULT_ADDR, null, VAULT_MAX_RETRIES.toString(), VAULT_TOKEN).execute(() -> {
            HTTPVaultConnectorFactory factory = assertDoesNotThrow(
                    () -> VaultConnectorFactory.httpFactory().fromEnv(),
                    "Factory creation from minimal environment failed"
            );
            assertThat("Token nor set correctly", getPrivate(getPrivate(factory, "delegate"), "token"), is(equalTo(VAULT_TOKEN)));

            return null;
        });
    }

    private SystemLambda.WithEnvironmentVariables withVaultEnv(String vault_addr, String vault_cacert, String vault_max_retries, String vault_token) {
        return withEnvironmentVariable("VAULT_ADDR", vault_addr)
                .and("VAULT_CACERT", vault_cacert)
                .and("VAULT_MAX_RETRIES", vault_max_retries)
                .and("VAULT_TOKEN", vault_token);
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
