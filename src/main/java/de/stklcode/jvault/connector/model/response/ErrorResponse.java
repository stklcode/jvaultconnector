package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Vault response in case of errors.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ErrorResponse implements VaultResponse {
    @JsonProperty("errors")
    private List<String> errors;

    public List<String > getErrors() {
        return errors;
    }
}