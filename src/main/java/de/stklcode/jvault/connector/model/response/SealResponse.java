package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Vault response for seal status or unseal request.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SealResponse implements VaultResponse {
    @JsonProperty("sealed")
    private boolean sealed;

    @JsonProperty("t")
    private Integer threshold;

    @JsonProperty("n")
    private Integer numberOfShares;

    @JsonProperty("progress")
    private Integer progress;

    public boolean isSealed() {
        return sealed;
    }

    public Integer getThreshold() {
        return threshold;
    }

    public Integer getNumberOfShares() {
        return numberOfShares;
    }

    public Integer getProgress() {
        return progress;
    }
}
