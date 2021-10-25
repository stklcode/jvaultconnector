/*
 * Copyright 2016-2022 Stefan Kalscheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.model.response.embedded.WrapInfo;

import java.util.List;
import java.util.Objects;

/**
 * Abstract Vault response with default payload fields.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public abstract class VaultDataResponse implements VaultResponse {
    private static final long serialVersionUID = 2507925101227179499L;

    @JsonProperty("lease_id")
    private String leaseId;

    @JsonProperty("renewable")
    private boolean renewable;

    @JsonProperty("lease_duration")
    private Integer leaseDuration;

    @JsonProperty("warnings")
    private List<String> warnings;

    @JsonProperty("wrap_info")
    private WrapInfo wrapInfo;

    /**
     * @return Lease ID
     */
    public final String getLeaseId() {
        return leaseId;
    }

    /**
     * @return Lease is renewable
     */
    public final boolean isRenewable() {
        return renewable;
    }

    /**
     * @return Lease duration
     */
    public final Integer getLeaseDuration() {
        return leaseDuration;
    }

    /**
     * @return List of warnings
     */
    public final List<String> getWarnings() {
        return warnings;
    }

    /**
     * @return Wrapping information
     * @since 1.1
     */
    public final WrapInfo getWrapInfo() {
        return wrapInfo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        VaultDataResponse that = (VaultDataResponse) o;
        return renewable == that.renewable &&
                Objects.equals(leaseId, that.leaseId) &&
                Objects.equals(leaseDuration, that.leaseDuration) &&
                Objects.equals(warnings, that.warnings) &&
                Objects.equals(wrapInfo, that.wrapInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(leaseId, renewable, leaseDuration, warnings, wrapInfo);
    }
}
