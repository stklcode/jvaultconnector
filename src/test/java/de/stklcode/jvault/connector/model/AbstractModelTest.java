package de.stklcode.jvault.connector.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import java.io.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Abstract testcase for model classes.
 *
 * @author Stefan Kalscheuer
 * @since 1.1
 */
public abstract class AbstractModelTest<T> {
    protected final Class<?> modelClass;
    protected final ObjectMapper objectMapper;

    /**
     * Test case constructor.
     *
     * @param modelClass Target class to test.
     */
    protected AbstractModelTest(Class<T> modelClass) {
        this.modelClass = modelClass;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Create a "full" model instance.
     *
     * @return Model instance.
     */
    protected abstract T createFull();

    /**
     * Test if {@link Object#equals(Object)} and {@link Object#hashCode()} are implemented, s.t. all fields are covered.
     */
    @Test
    void testEqualsHashcode() {
        EqualsVerifier.simple().forClass(modelClass).verify();
    }

    /**
     * Test Java serialization of a full model instance.
     * Serialization and deserialization must not fail and the resulting object should equal the original object.
     */
    @Test
    void serializationTest() {
        T original = createFull();
        byte[] bytes;
        try (var bos = new ByteArrayOutputStream();
             var oos = new ObjectOutputStream(bos)) {
            oos.writeObject(original);
            bytes = bos.toByteArray();
        } catch (IOException e) {
            fail("Serialization failed", e);
            return;
        }

        try (var bis = new ByteArrayInputStream(bytes);
             var ois = new ObjectInputStream(bis)) {
            Object copy = ois.readObject();
            assertEquals(modelClass, copy.getClass(), "Invalid class after deserialization");
            assertEquals(original, copy, "Deserialized object should be equal to the original");
        } catch (IOException | ClassNotFoundException e) {
            fail("Deserialization failed", e);
        }
    }
}
