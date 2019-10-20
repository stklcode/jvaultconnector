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

package de.stklcode.jvault.connector.test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test helper to modify system environment.
 *
 * @author Stefan Kalscheuer
 */
@SuppressWarnings("unchecked")
public class EnvironmentMock {
    private static Map<String, String> environment;

    static {
        try {
            Map<String, String> originalEnv = System.getenv();
            Field mapField = originalEnv.getClass().getDeclaredField("m");
            mapField.setAccessible(true);
            environment = (Map<String, String>) mapField.get(originalEnv);
        } catch (NoSuchFieldException | IllegalAccessException | ClassCastException e) {
            fail("Failed to intercept unmodifiable system environment");
        }
    }

    public static void setenv(String key, String value) {
        if (value != null) {
            environment.put(key, value);
        } else {
            environment.remove(key);
        }
    }
}
