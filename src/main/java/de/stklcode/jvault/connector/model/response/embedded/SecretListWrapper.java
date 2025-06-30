package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Wrapper object for secret key lists.
 *
 * @author Stefan Kalscheuer
 * @since 1.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretListWrapper implements Serializable {

    @Serial
    private static final long serialVersionUID = -8777605197063766125L;

    @JsonProperty("keys")
    private List<String> keys;

    public List<String> getKeys() {
        return keys;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SecretListWrapper that = (SecretListWrapper) o;
        return Objects.equals(keys, that.keys);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keys);
    }
}
