package de.stklcode.jvault.connector.model;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;

import java.util.Arrays;
import java.util.List;

/**
 * This custom deserializer supports lists, a single string or a comma-separated string for list fields.
 *
 * @author Stefan Kalscheuer
 * @since 2.0.0
 */
public class CommaSeparatedArrayDeserializer extends ValueDeserializer<List<String>> {

    @Override
    public List<String> deserialize(JsonParser p, DeserializationContext ctx) throws JacksonException {
        if (p.currentToken() == JsonToken.START_ARRAY) {
            return ctx.readValue(p, ctx.getTypeFactory().constructCollectionType(List.class, String.class));
        }

        // Handle plain string, either singleton or comma-separated.
        var value = p.getString();
        if (value == null) {
            return null;
        } else if (value.isBlank()) {
            return List.of();
        } else {
            return Arrays.asList(value.trim().split("\\s*,\\s*"));
        }
    }
}
