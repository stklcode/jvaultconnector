/*
 * Copyright 2016-2017 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.exception.InvalidResponseException;

import java.util.List;
import java.util.Map;

/**
 * Abstract Vault response with default payload fields.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
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

    /**
     * Set data. To be implemented in the specific subclasses, as data can be of arbitrary structure.
     *
     * @param data Raw response data
     * @throws InvalidResponseException on parsing errors
     */
    @JsonProperty("data")
    public abstract void setData(final Map<String, Object> data) throws InvalidResponseException;

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
}
