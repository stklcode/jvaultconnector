package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import de.stklcode.jvault.connector.exception.InvalidResponseException;

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
}