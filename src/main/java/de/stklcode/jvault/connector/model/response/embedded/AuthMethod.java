package de.stklcode.jvault.connector.model.response.embedded;


import de.stklcode.jvault.connector.model.AuthBackend;

/**
 * Embedded authentication method response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class AuthMethod {
    private AuthBackend type;
    private String rawType;
    private String path;
    private String description;

    public AuthMethod(String path, String description, String type) {
        this.path = path;
        this.description = description;
        this.rawType = type;
        this.type = AuthBackend.forType(type);
    }

    public AuthBackend getType() {
        return type;
    }

    public String getRawType() {
        return rawType;
    }

    public String getPath() {
        return path;
    }

    public String getDescription() {
        return description;
    }
}
