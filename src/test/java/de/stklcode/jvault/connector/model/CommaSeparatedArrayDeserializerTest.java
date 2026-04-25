package de.stklcode.jvault.connector.model;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link CommaSeparatedArrayDeserializer}
 */
class CommaSeparatedArrayDeserializerTest {

    private final ObjectMapper mapper = JsonMapper.builder().build();

    // Minimal test fixture to apply the deserializer.
    record TestClass(@JsonDeserialize(using = CommaSeparatedArrayDeserializer.class) List<String> values) {
    }


    @Test
    void shouldDeserializeJsonArray() {
        var result = mapper.readValue("""
            {"values": ["a", "b", "c"]}
            """, TestClass.class);
        assertEquals(List.of("a", "b", "c"), result.values(), "unexpected result for JSON array");
    }

    @Test
    void shouldDeserializeCommaSeparatedString() {
        var result = mapper.readValue("""
            {"values": "a,b,c"}
            """, TestClass.class);
        assertEquals(List.of("a", "b", "c"), result.values(), "unexpected result for comma-separated list");
    }

    @Test
    void shouldTrimWhitespaceInCommaSeparatedString() {
        var result = mapper.readValue("""
            {"values": "a,b , c "}
            """, TestClass.class);
        assertEquals(List.of("a", "b", "c"), result.values(), "unexpected result for comma-separated list with spaces");
    }

    @Test
    void shouldDeserializeSingleElementString() {
        var result = mapper.readValue("""
            {"values": "a"}
            """, TestClass.class);
        assertEquals(List.of("a"), result.values(), "single string should be converted to singleton list");
    }

    @Test
    void shouldReturnEmptyListForBlankString() {
        var result = mapper.readValue("""
            {"values": "   "}
            """, TestClass.class);
        assertNotNull(result.values(), "blank string should not result in null values");
        assertTrue(result.values().isEmpty(), "blank string should be converted to empty list");
    }

    @Test
    void shouldReturnNullForJsonNull() {
        var result = mapper.readValue("""
            {"values": null}
            """, TestClass.class);
        assertNull(result.values(), "null JSON should return null values");
    }

    @Test
    void shouldDeserializeEmptyArray() {
        var result = mapper.readValue("""
            {"values": []}
            """, TestClass.class);
        assertNotNull(result.values(), "empty list should not be null");
        assertTrue(result.values().isEmpty(), "empty list should be empty");
    }
}
