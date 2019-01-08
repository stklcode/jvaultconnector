/*
 * Copyright 2016-2019 Stefan Kalscheuer
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
public final class AuthData {
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

    /**
     * @return Client token
     */
    public String getClientToken() {
        return clientToken;
    }

    /**
     * @return Token accessor
     */
    public String getAccessor() {
        return accessor;
    }

    /**
     * @return List of policies
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * @return Metadata
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * @return Lease duration
     */
    public Integer getLeaseDuration() {
        return leaseDuration;
    }

    /**
     * @return Lease is renewable
     */
    public boolean isRenewable() {
        return renewable;
    }
}
