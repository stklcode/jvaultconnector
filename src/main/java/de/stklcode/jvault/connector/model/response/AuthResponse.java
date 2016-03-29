package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;

import java.io.IOException;
import java.util.Map;

/**
 * Vault response for authentication providing auth info in {@link AuthData} field.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthResponse extends VaultDataResponse {
    private Map<String, Object> data;

    private AuthData auth;

    @JsonProperty("auth")
    public void setAuth(Map<String, Object> auth) throws InvalidResponseException {
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.auth = mapper.readValue(mapper.writeValueAsString(auth), AuthData.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new InvalidResponseException();
        }
    }

    @Override
    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    public Map<String, Object> getData() {
        return data;
    }

    public AuthData getAuth() {
        return auth;
    }
}
