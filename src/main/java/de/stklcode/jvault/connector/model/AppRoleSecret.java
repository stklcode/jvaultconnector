/*
 * Copyright 2016-2021 Stefan Kalscheuer
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

import java.util.List;
import java.util.Map;

/**
 * Vault AppRole role metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppRoleSecret {
    @JsonProperty("secret_id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    @JsonProperty(value = "secret_id_accessor", access = JsonProperty.Access.WRITE_ONLY)
    private String accessor;

    @JsonProperty("metadata")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Map<String, Object> metadata;

    private List<String> cidrList;

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
}
