package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.exception.InvalidResponseException;

import java.util.List;
import java.util.Map;

/**
 * Vault response for secret list request.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretListResponse extends VaultDataResponse {
    private List<String> keys;

    @JsonProperty("data")
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        try {
            this.keys = (List<String>)data.get("keys");
        }
        catch (ClassCastException e) {
            throw new InvalidResponseException("Keys could not be parsed from data.", e);
        }
    }

    public List<String> getKeys() {
        return keys;
    }
}
