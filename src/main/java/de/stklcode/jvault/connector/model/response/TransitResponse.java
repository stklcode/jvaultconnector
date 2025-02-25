package de.stklcode.jvault.connector.model.response;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TransitResponse extends VaultDataResponse {
        private static final long serialVersionUID = -4823865538268326557L;

    @JsonProperty("data")
    private Map<String, Serializable> data;

    //@Override
    public final Map<String, Serializable> getData() {
        return Objects.requireNonNullElseGet(data, Collections::emptyMap);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        TransitResponse that = (TransitResponse) o;
        return Objects.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), data);
    }
}
