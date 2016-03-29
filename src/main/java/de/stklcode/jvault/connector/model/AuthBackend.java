package de.stklcode.jvault.connector.model;

/**
 * Currently supported authentication backends.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public enum AuthBackend {
    TOKEN("token"),
    APPID("app-id"),
    USERPASS("userpass"),
    UNKNOWN("");

    private final String type;

    AuthBackend(String type) {
        this.type = type;
    }

    public static AuthBackend forType(String type) {
        for (AuthBackend v : values())
            if (v.type.equalsIgnoreCase(type))
                return v;
        return UNKNOWN;
    }
}
