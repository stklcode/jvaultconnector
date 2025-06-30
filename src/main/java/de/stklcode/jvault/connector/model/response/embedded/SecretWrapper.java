package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;
import java.util.Objects;

/**
 * Wrapper object for secret data and metadata.
 *
 * @author Stefan Kalscheuer
 * @since 1.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretWrapper implements Serializable {
    @Serial
    private static final long serialVersionUID = 8600413181758893378L;

    @JsonProperty("data")
    private Map<String, Serializable> data;

    @JsonProperty("metadata")
    private VersionMetadata metadata;

    public Map<String, Serializable> getData() {
        return data;
    }

    public VersionMetadata getMetadata() {
        return metadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SecretWrapper that = (SecretWrapper) o;
        return Objects.equals(data, that.data) && Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(data, metadata);
    }
}
