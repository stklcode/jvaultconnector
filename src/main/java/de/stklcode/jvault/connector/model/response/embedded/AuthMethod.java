package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import de.stklcode.jvault.connector.model.AuthBackend;

import java.util.Map;

/**
 * Embedded authentication method response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class AuthMethod {
    private AuthBackend type;
    private String rawType;

    @JsonProperty("description")
    private String description;

    @JsonProperty("config")
    private Map<String, String> config;

    @JsonSetter("type")
    public void setType(String type) {
        this.rawType = type;
        this.type = AuthBackend.forType(type);
    }

    public AuthBackend getType() {
        return type;
    }

    public String getRawType() {
        return rawType;
    }

    public String getDescription() {
        return description;
    }

    public Map<String, String> getConfig() {
        return config;
    }
}
