package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;

import java.io.IOException;
import java.util.Map;

/**
 * Vault response for secret request.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretResponse extends VaultDataResponse {
    private String value;

    @Override
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        try {
            this.value = (String) data.get("value");
        } catch (ClassCastException e) {
            throw new InvalidResponseException("Value could not be parsed", e);
        }
    }

    public String getValue() {
        return value;
    }

    /**
     * Get response parsed as JSON
     * @param type  Class to parse response
     * @param <T>   Class to parse response
     * @return      Parsed object
     * @throws InvalidResponseException on parsing error
     * @since 0.3
     */
    public <T> T getValue(Class<T> type) throws InvalidResponseException {
        try {
            return new ObjectMapper().readValue(getValue(), type);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response payload: " + e.getMessage());
        }
    }
}