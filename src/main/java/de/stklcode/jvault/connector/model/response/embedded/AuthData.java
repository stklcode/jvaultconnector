/*
 * Copyright 2016-2026 Stefan Kalscheuer
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

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Embedded authorization information inside Vault response.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 1.1 implements {@link Serializable}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuthData implements Serializable {
    private static final long serialVersionUID = 5969334512309655317L;

    @JsonProperty("client_token")
    private String clientToken;

    @JsonProperty("accessor")
    private String accessor;

    @JsonProperty("policies")
    private List<String> policies;

    @JsonProperty("token_policies")
    private List<String> tokenPolicies;

    @JsonProperty("metadata")
    private Map<String, Object> metadata;

    @JsonProperty("lease_duration")
    private Integer leaseDuration;

    @JsonProperty("renewable")
    private boolean renewable;

    @JsonProperty("entity_id")
    private String entityId;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("orphan")
    private boolean orphan;

    @JsonProperty("num_uses")
    private Integer numUses;

    @JsonProperty("mfa_requirement")
    private MfaRequirement mfaRequirement;

    /**
     * @return Client token
     */
    public String getClientToken() {
        return clientToken;
    }

    /**
     * @return Token type
     * @since 0.9
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * @return List of policies
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * @return List of policies associated with the token
     * @since 0.9
     */
    public List<String> getTokenPolicies() {
        return tokenPolicies;
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

    /**
     * @return Entity ID
     * @since 0.9
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * @return Token accessor
     */
    public String getAccessor() {
        return accessor;
    }

    /**
     * @return allowed number of uses for the issued token
     * @since 1.3
     */
    public Integer getNumUses() {
        return numUses;
    }

    /**
     * @return Token is orphan
     * @since 0.9
     */
    public boolean isOrphan() {
        return orphan;
    }

    /**
     * @return multi-factor requirement
     * @since 1.2
     */
    public MfaRequirement getMfaRequirement() {
        return mfaRequirement;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthData authData = (AuthData) o;
        return renewable == authData.renewable &&
            orphan == authData.orphan &&
            Objects.equals(clientToken, authData.clientToken) &&
            Objects.equals(accessor, authData.accessor) &&
            Objects.equals(policies, authData.policies) &&
            Objects.equals(tokenPolicies, authData.tokenPolicies) &&
            Objects.equals(metadata, authData.metadata) &&
            Objects.equals(leaseDuration, authData.leaseDuration) &&
            Objects.equals(entityId, authData.entityId) &&
            Objects.equals(tokenType, authData.tokenType) &&
            Objects.equals(numUses, authData.numUses) &&
            Objects.equals(mfaRequirement, authData.mfaRequirement);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientToken, accessor, policies, tokenPolicies, metadata, leaseDuration, renewable,
            entityId, tokenType, orphan, numUses, mfaRequirement);
    }
}
