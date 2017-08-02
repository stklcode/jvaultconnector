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

package de.stklcode.jvault.connector.model;

import com.fasterxml.jackson.annotation.*;

import java.util.Arrays;
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

    public AppRoleSecret() {

    }

    public AppRoleSecret(final String id) {
        this.id = id;
    }

    public AppRoleSecret(final String id, final Map<String, Object> metadata, final List<String> cidrList) {
        this.id = id;
        this.metadata = metadata;
        this.cidrList = cidrList;
    }

    public String getId() {
        return id;
    }

    public String getAccessor() {
        return accessor;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public List<String> getCidrList() {
        return cidrList;
    }

    @JsonSetter("cidr_list")
    public void setCidrList(final List<String> cidrList) {
        this.cidrList = cidrList;
    }

    @JsonGetter("cidr_list")
    public String getCidrListString() {
        if (cidrList == null || cidrList.isEmpty())
            return "";
        return String.join(",", cidrList);
    }

    public String getCreationTime() {
        return creationTime;
    }

    public String getExpirationTime() {
        return expirationTime;
    }

    public String getLastUpdatedTime() {
        return lastUpdatedTime;
    }

    public Integer getNumUses() {
        return numUses;
    }

    public Integer getTtl() {
        return ttl;
    }
}
