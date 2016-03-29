package de.stklcode.jvault.connector.model.response;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.TokenData;

import java.io.IOException;
import java.util.Map;

/**
 * Vault response from token lookup providing Token information in {@link TokenData} field.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenResponse extends VaultDataResponse {
    private TokenData data;

    @JsonProperty("auth")
    private Boolean auth;

    @Override
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.data = mapper.readValue(mapper.writeValueAsString(data), TokenData.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new InvalidResponseException();
        }
    }

    public TokenData getData() {
        return data;
    }
}
