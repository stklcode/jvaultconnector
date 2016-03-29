package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authentication method response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class AuthMethodsResponse implements VaultResponse {

    private List<AuthMethod> supportedMethods;

    @JsonAnySetter
    public void setMethod(String path, Map<String, String> data) throws InvalidResponseException {
        if (supportedMethods == null)
            supportedMethods = new ArrayList<>();

        supportedMethods.add(new AuthMethod(path, data.get("description"), data.get("type")));
    }

    public List<AuthMethod> getSupportedMethods() {
        return supportedMethods;
    }
}
