package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Embedded authorization information inside Vault response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthData {
    @JsonProperty("client_token")
    private String clientToken;

    @JsonProperty("accessor")
    private String accessor;

    @JsonProperty("policies")
    private List<String> policies;

    @JsonProperty("metadata")
    private Map<String, Object> metadata;

    @JsonProperty("lease_duration")
    private Integer leaseDuration;

    @JsonProperty("renewable")
    private boolean renewable;

    public String getClientToken() {
        return clientToken;
    }

    public String getAccessor() {
        return accessor;
    }

    public List<String> getPolicies() {
        return policies;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public Integer getLeaseDuration() {
        return leaseDuration;
    }

    public boolean isRenewable() {
        return renewable;
    }
}