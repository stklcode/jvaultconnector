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

package de.stklcode.jvault.connector.model;

import com.fasterxml.jackson.annotation.*;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Vault AppRole role metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @since 1.1 implements {@link Serializable}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppRoleSecret implements Serializable {
    private static final long serialVersionUID = 3079272087137299819L;

    @JsonProperty("secret_id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    @JsonProperty(value = "secret_id_accessor", access = JsonProperty.Access.WRITE_ONLY)
    private String accessor;

    @JsonProperty("metadata")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Map<String, Object> metadata;

    private List<String> cidrList;

    private List<String> tokenBoundCidrs;

    @JsonProperty(value = "creation_time", access = JsonProperty.Access.WRITE_ONLY)
    private String creationTime;

    @JsonProperty(value = "expiration_time", access = JsonProperty.Access.WRITE_ONLY)
    private String expirationTime;

    @JsonProperty(value = "last_updated_time", access = JsonProperty.Access.WRITE_ONLY)
    private String lastUpdatedTime;

    @JsonProperty(value = "secret_id_num_uses", access = JsonProperty.Access.WRITE_ONLY)
    private Integer numUses;

    @JsonProperty(value = "secret_id_ttl", access = JsonProperty.Access.WRITE_ONLY)
    private Integer ttl;

    /**
     * Construct empty {@link AppRoleSecret} object.
     */
    public AppRoleSecret() {
    }

    /**
     * Construct {@link AppRoleSecret} with secret ID.
     *
     * @param id Secret ID
     */
    public AppRoleSecret(final String id) {
        this.id = id;
    }

    /**
     * Construct {@link AppRoleSecret} with ID and metadata.
     *
     * @param id       Secret ID
     * @param metadata Secret metadata
     * @param cidrList List of subnets in CIDR notation, the role is bound to
     */
    public AppRoleSecret(final String id, final Map<String, Object> metadata, final List<String> cidrList) {
        this.id = id;
        this.metadata = metadata;
        this.cidrList = cidrList;
    }

    /**
     * @return Secret ID
     */
    public String getId() {
        return id;
    }

    /**
     * @return Secret accessor
     */
    public String getAccessor() {
        return accessor;
    }

    /**
     * @return Secret metadata
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * @return List of bound subnets in CIDR notation
     */
    public List<String> getCidrList() {
        return cidrList;
    }

    /**
     * @param cidrList List of subnets in CIDR notation
     */
    @JsonSetter("cidr_list")
    public void setCidrList(final List<String> cidrList) {
        this.cidrList = cidrList;
    }

    /**
     * @return List of bound subnets in CIDR notation as comma-separated {@link String}
     */
    @JsonGetter("cidr_list")
    public String getCidrListString() {
        if (cidrList == null || cidrList.isEmpty()) {
            return "";
        }
        return String.join(",", cidrList);
    }

    /**
     * @return list of bound CIDR subnets of associated tokens
     * @since 1.5.3
     */
    public List<String> getTokenBoundCidrs() {
        return tokenBoundCidrs;
    }

    /**
     * @param boundCidrList list of subnets in CIDR notation to bind role to
     * @since 1.5.3
     */
    @JsonSetter("token_bound_cidrs")
    public void setTokenBoundCidrs(final List<String> boundCidrList) {
        this.tokenBoundCidrs = boundCidrList;
    }

    /**
     * @return list of subnets in CIDR notation as comma-separated {@link String}
     * @since 1.5.3
     */
    @JsonGetter("token_bound_cidrs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getTokenBoundCidrsString() {
        if (tokenBoundCidrs == null || tokenBoundCidrs.isEmpty()) {
            return "";
        }
        return String.join(",", tokenBoundCidrs);
    }

    /**
     * @return Creation time
     */
    public String getCreationTime() {
        return creationTime;
    }

    /**
     * @return Expiration time
     */
    public String getExpirationTime() {
        return expirationTime;
    }

    /**
     * @return Time of last update
     */
    public String getLastUpdatedTime() {
        return lastUpdatedTime;
    }

    /**
     * @return Number of uses
     */
    public Integer getNumUses() {
        return numUses;
    }

    /**
     * @return Time-to-live
     */
    public Integer getTtl() {
        return ttl;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AppRoleSecret that = (AppRoleSecret) o;
        return Objects.equals(id, that.id) &&
            Objects.equals(accessor, that.accessor) &&
            Objects.equals(metadata, that.metadata) &&
            Objects.equals(cidrList, that.cidrList) &&
            Objects.equals(tokenBoundCidrs, that.tokenBoundCidrs) &&
            Objects.equals(creationTime, that.creationTime) &&
            Objects.equals(expirationTime, that.expirationTime) &&
            Objects.equals(lastUpdatedTime, that.lastUpdatedTime) &&
            Objects.equals(numUses, that.numUses) &&
            Objects.equals(ttl, that.ttl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, accessor, metadata, cidrList, tokenBoundCidrs, creationTime, expirationTime,
            lastUpdatedTime, numUses, ttl);
    }
}
