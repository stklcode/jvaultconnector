package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication method response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthMethodsResponse extends VaultDataResponse {
    private Map<String, AuthMethod> supportedMethods;

    public AuthMethodsResponse() {
        this.supportedMethods = new HashMap<>();
    }

    @Override
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        ObjectMapper mapper = new ObjectMapper();
        for (String path : data.keySet()) {
            try {
                this.supportedMethods.put(path, mapper.readValue(mapper.writeValueAsString(data.get(path)), AuthMethod.class));
            } catch (IOException e) {
                throw new InvalidResponseException();
            }
        }
    }

    public Map<String, AuthMethod> getSupportedMethods() {
        return supportedMethods;
    }
}
