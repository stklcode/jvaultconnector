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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.util.List;

/**
 * Vault AppRole role metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AppRole {
    @JsonProperty("role_name")
    private String name;

    @JsonProperty("role_id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    @JsonProperty("bind_secret_id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean bindSecretId;

    private List<String> boundCidrList;

    private List<String> policies;

    @JsonProperty("secret_id_num_uses")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer secretIdNumUses;

    @JsonProperty("secret_id_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer secretIdTtl;

    @JsonProperty("token_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenTtl;

    @JsonProperty("token_max_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenMaxTtl;

    @JsonProperty("period")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer period;

    public AppRole() {

    }

    public AppRole(String name, String id, Boolean bindSecretId, List<String> boundCidrList, List<String> policies, Integer secretIdNumUses, Integer secretIdTtl, Integer tokenTtl, Integer tokenMaxTtl, Integer period) {
        this.name = name;
        this.id = id;
        this.bindSecretId = bindSecretId;
        this.boundCidrList = boundCidrList;
        this.policies = policies;
        this.secretIdNumUses = secretIdNumUses;
        this.secretIdTtl = secretIdTtl;
        this.tokenTtl = tokenTtl;
        this.tokenMaxTtl = tokenMaxTtl;
        this.period = period;
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public Boolean getBindSecretId() {
        return bindSecretId;
    }

    public List<String> getBoundCidrList() {
        return boundCidrList;
    }

    @JsonSetter("bound_cidr_list")
    public void setBoundCidrList(List<String> boundCidrList) {
        this.boundCidrList = boundCidrList;
    }

    @JsonGetter("bound_cidr_list")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getBoundCidrListString() {
        if (boundCidrList == null || boundCidrList.isEmpty())
            return "";
        return String.join(",", boundCidrList);
    }

    public List<String> getPolicies() {
        return policies;
    }

    @JsonSetter("policies")
    public void setPolicies(List<String> policies) {
        this.policies = policies;
    }

    @JsonGetter("policies")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getPoliciesString() {
        if (policies == null || policies.isEmpty())
            return "";
        return String.join(",", policies);
    }

    public Integer getSecretIdNumUses() {
        return secretIdNumUses;
    }

    public Integer getSecretIdTtl() {
        return secretIdTtl;
    }

    public Integer getTokenTtl() {
        return tokenTtl;
    }

    public Integer getTokenMaxTtl() {
        return tokenMaxTtl;
    }

    public Integer getPeriod() {
        return period;
    }
}
