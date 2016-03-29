package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.exception.InvalidResponseException;

import java.util.List;
import java.util.Map;

/**
 * Abstract Vault response with default payload fields.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public abstract class VaultDataResponse implements VaultResponse {
    @JsonProperty("lease_id")
    private String leaseId;

    @JsonProperty("renewable")
    private boolean renewable;

    @JsonProperty("lease_duration")
    private Integer leaseDuration;

    @JsonProperty("warnings")
    private List<String> warnings;

    @JsonProperty("data")
    public abstract void setData(Map<String, Object> data) throws InvalidResponseException;

    public String getLeaseId() {
        return leaseId;
    }

    public boolean isRenewable() {
        return renewable;
    }

    public Integer getLeaseDuration() {
        return leaseDuration;
    }

    public List<String> getWarnings() {
        return warnings;
    }
}
