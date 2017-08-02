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

import java.util.List;

/**
 * Vault AppRole role metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppRole {
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

    /**
     * Construct empty {@link AppRole} object.
     */
    public AppRole() {

    }

    /**
     * Construct complete {@link AppRole} object.
     *
     * @param name            Role name (required)
     * @param id              Role ID (optional)
     * @param bindSecretId    Bind secret ID (optional)
     * @param boundCidrList   Whitelist of subnets in CIDR notation (optional)
     * @param policies        List of policies (optional)
     * @param secretIdNumUses Maximum number of uses per secret (optional)
     * @param secretIdTtl     Maximum TTL in seconds for secrets (optional)
     * @param tokenTtl        Token TTL in seconds (optional)
     * @param tokenMaxTtl     Maximum token TTL in seconds, including renewals (optional)
     * @param period          Duration in seconds, if set the token is a periodic token (optional)
     */
    public AppRole(final String name, final String id, final Boolean bindSecretId, final List<String> boundCidrList,
                   final List<String> policies, final Integer secretIdNumUses, final Integer secretIdTtl,
                   final Integer tokenTtl, final Integer tokenMaxTtl, final Integer period) {
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

    /**
     * @return the role name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the role ID
     */
    public String getId() {
        return id;
    }

    /**
     * @return bind secret ID
     */
    public Boolean getBindSecretId() {
        return bindSecretId;
    }

    /**
     * @return list of bound CIDR subnets
     */
    public List<String> getBoundCidrList() {
        return boundCidrList;
    }

    /**
     * @param boundCidrList list of subnets in CIDR notation to bind role to
     */
    @JsonSetter("bound_cidr_list")
    public void setBoundCidrList(final List<String> boundCidrList) {
        this.boundCidrList = boundCidrList;
    }

    /**
     * @return list of subnets in CIDR notation as comma-separated {@link String}
     */
    @JsonGetter("bound_cidr_list")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getBoundCidrListString() {
        if (boundCidrList == null || boundCidrList.isEmpty())
            return "";
        return String.join(",", boundCidrList);
    }

    /**
     * @return list of policies
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * @param policies list of policies
     */
    @JsonSetter("policies")
    public void setPolicies(final List<String> policies) {
        this.policies = policies;
    }

    /**
     * @return list of policies as comma-separated {@link String}
     */
    @JsonGetter("policies")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getPoliciesString() {
        if (policies == null || policies.isEmpty())
            return "";
        return String.join(",", policies);
    }

    /**
     * @return maximum number of uses per secret
     */
    public Integer getSecretIdNumUses() {
        return secretIdNumUses;
    }

    /**
     * @return maximum TTL in seconds for secrets
     */
    public Integer getSecretIdTtl() {
        return secretIdTtl;
    }

    /**
     * @return token TTL in seconds
     */
    public Integer getTokenTtl() {
        return tokenTtl;
    }

    /**
     * @return maximum token TTL in seconds, including renewals
     */
    public Integer getTokenMaxTtl() {
        return tokenMaxTtl;
    }

    /**
     * @return duration in seconds, if specified
     */
    public Integer getPeriod() {
        return period;
    }
}
