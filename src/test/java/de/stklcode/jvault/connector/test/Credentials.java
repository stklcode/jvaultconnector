package de.stklcode.jvault.connector.test;


import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Simple credentials class for JSON testing.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class Credentials {
    @JsonProperty("username")
    private String username;

    @JsonProperty("password")
    private String password;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
