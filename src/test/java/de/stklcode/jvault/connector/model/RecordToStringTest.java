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

import de.stklcode.jvault.connector.model.response.PkiResponse;
import de.stklcode.jvault.connector.model.response.PlainSecretResponse;
import de.stklcode.jvault.connector.model.response.TransitResponse;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Canary test for {@code toString()} of all model records.
 * <p>
 * Every record is instantiated with a unique canary value in each (nested) leaf component.
 * The string representation must not contain canaries of masked or summarized components,
 * but must contain all others.
 */
class RecordToStringTest {
    private static final String MODEL_PACKAGE = "de.stklcode.jvault.connector.model";

    /**
     * Components that must never be printed, neither masked nor summarized.
     * Key format: {@code SimpleName.component}, nested records as {@code Outer.Inner.component}.
     */
    private static final Set<String> HIDDEN = Set.of(
        // Secrets (masked).
        "AppRoleSecret.id",
        "Token.id",
        "AuthData.clientToken",
        "MfaRequirement.mfaRequestId",
        "TokenData.id",
        "WrapInfo.token",
        "PkiResponse.Data.privateKey",
        "TransitResponse.Data.plaintext",
        "CredentialsResponse.data",
        "PlainSecretResponse.data",
        "RawDataResponse.data",
        "SecretWrapper.data",
        // Long values (summarized or abbreviated).
        "PkiCaResponse.Data.caChain",
        "PkiCaResponse.Data.certificate",
        "PkiResponse.Data.caChain",
        "PkiResponse.Data.certificate",
        "PkiResponse.Data.issuingCa",
        "TransitResponse.Data.ciphertext"
    );

    /**
     * Components whose name looks sensitive, but which are deliberately printed.
     */
    private static final Set<String> VISIBLE = Set.of(
        "AppRole.id",                       // Role ID is an identifier, not a secret.
        "MfaMethodId.id",                   // MFA method ID.
        "SealResponse.nonce",               // Progress nonce for rekey/root generation.
        "VaultDataResponse.Header.requestId"
    );

    /**
     * Component names that are likely sensitive. A new component matching this pattern must be added to
     * either {@link #HIDDEN} or {@link #VISIBLE}.
     */
    private static final Pattern SENSITIVE_NAME = Pattern.compile(
        "(?i)^(id|.*token|.*secret|.*password|.*privatekey|.*plaintext|.*requestid|.*nonce)$"
    );

    /**
     * Canary value for given component key.
     */
    private static String canary(String key) {
        return "CANARY<" + key + ">";
    }

    @TestFactory
    Stream<DynamicTest> canaryTest() throws Exception {
        List<Class<?>> records = modelRecords();
        assertTrue(records.size() > 30, "Too few records found, discovery broken? " + records);

        return records.stream().map(cls -> DynamicTest.dynamicTest(name(cls), () -> {
            List<String> leaves = new ArrayList<>();
            Object instance = instantiate(cls, leaves);
            String str = assertDoesNotThrow(instance::toString, "toString() failed");

            for (String key : leaves) {
                if (HIDDEN.contains(key)) {
                    assertFalse(str.contains(canary(key)), "Hidden component " + key + " printed: " + str);
                } else {
                    assertTrue(str.contains(canary(key)), "Component " + key + " not printed: " + str);
                }
            }
        }));
    }

    @TestFactory
    Stream<DynamicTest> nullValueTest() throws Exception {
        return modelRecords().stream().map(cls -> DynamicTest.dynamicTest(name(cls), () -> {
            var ctor = cls.getDeclaredConstructor(
                Arrays.stream(cls.getRecordComponents()).map(RecordComponent::getType).toArray(Class[]::new)
            );
            Object[] args = Arrays.stream(cls.getRecordComponents()).map(c -> defaultValue(c.getType())).toArray();
            Object instance = ctor.newInstance(args);
            assertDoesNotThrow(instance::toString, "toString() failed with null values");
        }));
    }

    /**
     * Guard against new sensitive components that are printed without an explicit decision.
     */
    @Test
    void sensitiveNamesClassifiedTest() throws Exception {
        List<String> unclassified = new ArrayList<>();
        for (Class<?> cls : modelRecords()) {
            for (RecordComponent c : cls.getRecordComponents()) {
                String key = name(cls) + "." + c.getName();
                if (SENSITIVE_NAME.matcher(c.getName()).matches() && isLeaf(c.getType())
                    && !HIDDEN.contains(key) && !VISIBLE.contains(key)) {
                    unclassified.add(key);
                }
            }
        }
        assertEquals(List.of(), unclassified, "Potentially sensitive components must be classified as HIDDEN or VISIBLE");

        // All configured keys must exist, so typos and removed fields are detected.
        Set<String> existing = new HashSet<>();
        for (Class<?> cls : modelRecords()) {
            for (RecordComponent c : cls.getRecordComponents()) {
                existing.add(name(cls) + "." + c.getName());
            }
        }
        for (String key : HIDDEN) {
            assertTrue(existing.contains(key), "Unknown HIDDEN component " + key);
        }
        for (String key : VISIBLE) {
            assertTrue(existing.contains(key), "Unknown VISIBLE component " + key);
        }
    }

    /**
     * Some explicit examples of the output format.
     */
    @Test
    void formatTest() {
        var auth = new AuthData("s.secret", "acc", null, null, null, 60, true, null, "service", false, null, null);
        assertTrue(auth.toString().startsWith("AuthData[clientToken=***, accessor=acc, "), auth.toString());

        var secret = new PlainSecretResponse(null, Map.of("username", "user"));
        assertEquals("PlainSecretResponse[responseHeader=null, data={username=***}]", secret.toString());

        var pki = new PkiResponse.Data(1L, "-----BEGIN CERTIFICATE-----", null, List.of("a", "b"), null, "rsa", "01:02");
        assertEquals(
            "Data[expiration=1, certificate=<27 chars>, issuingCa=null, caChain=<2 entries>, privateKey=null, " +
                "privateKeyType=rsa, serialNumber=01:02]",
            pki.toString()
        );

        var transit = new TransitResponse.Data("vault:v1:abcdefghijklmnopqrstuvwxyz", "cGxhaW4=", null);
        assertEquals(
            "Data[ciphertext=vault:v1:abcdefg…<35 chars>, plaintext=***, sum=null]",
            transit.toString()
        );
    }

    /**
     * Discover all records in the model packages.
     */
    private static List<Class<?>> modelRecords() throws URISyntaxException, IOException, ClassNotFoundException {
        Path root = Path.of(Token.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path pkg = root.resolve(MODEL_PACKAGE.replace('.', '/'));
        List<Class<?>> result = new ArrayList<>();
        try (Stream<Path> files = Files.walk(pkg)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".class")).sorted().toList()) {
                String className = root.relativize(f).toString()
                    .replace(f.getFileSystem().getSeparator(), ".")
                    .replaceAll("\\.class$", "");
                Class<?> cls = Class.forName(className);
                if (cls.isRecord()) {
                    result.add(cls);
                }
            }
        }
        return result;
    }

    /**
     * Name of a (nested) record class, e.g. {@code PkiResponse.Data}.
     */
    private static String name(Class<?> cls) {
        return cls.getEnclosingClass() != null ? name(cls.getEnclosingClass()) + "." + cls.getSimpleName() : cls.getSimpleName();
    }

    /**
     * Create a record instance with canary values in all leaf components.
     */
    private static Object instantiate(Class<?> cls, List<String> leaves) throws ReflectiveOperationException {
        RecordComponent[] components = cls.getRecordComponents();
        Class<?>[] types = Arrays.stream(components).map(RecordComponent::getType).toArray(Class[]::new);
        Object[] args = new Object[components.length];
        for (int i = 0; i < components.length; i++) {
            String key = name(cls) + "." + components[i].getName();
            args[i] = value(components[i].getGenericType(), key, leaves);
        }
        return cls.getDeclaredConstructor(types).newInstance(args);
    }

    /**
     * Create a value for the given type. Leaf values carry the canary of the given component key.
     */
    private static Object value(Type type, String key, List<String> leaves) throws ReflectiveOperationException {
        Class<?> raw = type instanceof ParameterizedType pt ? (Class<?>) pt.getRawType() : (Class<?>) type;

        if (raw == String.class || raw == Object.class || raw == Serializable.class) {
            leaves.add(key);
            return canary(key);
        } else if (raw.isRecord()) {
            return instantiate(raw, leaves);
        } else if (List.class.isAssignableFrom(raw)) {
            Type elem = ((ParameterizedType) type).getActualTypeArguments()[0];
            return List.of(value(elem, key, leaves));
        } else if (Map.class.isAssignableFrom(raw)) {
            Type[] args = ((ParameterizedType) type).getActualTypeArguments();
            Object mapKey = args[0] == Integer.class ? Integer.valueOf(42) : "key";
            Map<Object, Object> map = new HashMap<>();
            map.put(mapKey, value(args[1], key, leaves));
            return map;
        } else if (raw == Integer.class || raw == int.class) {
            return 42;
        } else if (raw == Long.class || raw == long.class) {
            return 42L;
        } else if (raw == Boolean.class || raw == boolean.class) {
            return true;
        } else if (raw == ZonedDateTime.class) {
            return ZonedDateTime.parse("2026-01-01T00:00:00Z");
        }
        fail("Unsupported component type " + type + " for " + key + ", extend the test");
        return null;
    }

    private static boolean isLeaf(Class<?> type) {
        return type == String.class || type == Object.class || type == Serializable.class
            || List.class.isAssignableFrom(type) || Map.class.isAssignableFrom(type);
    }

    private static Object defaultValue(Class<?> type) {
        if (type == int.class) {
            return 0;
        } else if (type == long.class) {
            return 0L;
        } else if (type == boolean.class) {
            return false;
        }
        return null;
    }
}
