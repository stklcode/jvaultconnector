/*
 * Copyright 2016-2020 Stefan Kalscheuer
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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Vault Token Role metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.9
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class TokenRole {
    /**
     * Get {@link TokenRoleBuilder} instance.
     *
     * @return Token Role Builder.
     * @since 0.9
     */
    public static TokenRoleBuilder builder() {
        return new TokenRoleBuilder();
    }

    @JsonProperty("name")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String name;

    @JsonProperty("allowed_policies")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> allowedPolicies;

    @JsonProperty("disallowed_policies")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> disallowedPolicies;

    @JsonProperty("orphan")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean orphan;

    @JsonProperty("renewable")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean renewable;

    @JsonProperty("path_suffix")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String pathSuffix;

    @JsonProperty("allowed_entity_aliases")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> allowedEntityAliases;

    @JsonProperty("token_bound_cidrs")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> tokenBoundCidrs;

    @JsonProperty("token_explicit_max_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenExplicitMaxTtl;

    @JsonProperty("token_no_default_policy")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean tokenNoDefaultPolicy;

    @JsonProperty("token_num_uses")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenNumUses;

    @JsonProperty("token_period")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenPeriod;

    @JsonProperty("token_type")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String tokenType;


    /**
     * Construct complete {@link TokenRole} object.
     *
     * @param name                 Token Role name (redundant for creation).
     * @param allowedPolicies      Allowed policies (optional)
     * @param disallowedPolicies   Disallowed policies (optional)
     * @param orphan               Role is orphan? (optional)
     * @param renewable            Role is renewable? (optional)
     * @param pathSuffix           Paht suffix (optional)
     * @param allowedEntityAliases Allowed entity aliases (optional)
     * @param tokenBoundCidrs      Token bound CIDR blocks (optional)
     * @param tokenExplicitMaxTtl  Token explicit maximum TTL (optional)
     * @param tokenNoDefaultPolicy Token wihtout default policy? (optional)
     * @param tokenNumUses         Token number of uses (optional)
     * @param tokenPeriod          Token period (optional)
     * @param tokenType            Token type (optional)
     */
    public TokenRole(final String name,
                     final List<String> allowedPolicies,
                     final List<String> disallowedPolicies,
                     final Boolean orphan,
                     final Boolean renewable,
                     final String pathSuffix,
                     final List<String> allowedEntityAliases,
                     final List<String> tokenBoundCidrs,
                     final Integer tokenExplicitMaxTtl,
                     final Boolean tokenNoDefaultPolicy,
                     final Integer tokenNumUses,
                     final Integer tokenPeriod,
                     final String tokenType) {
        this.name = name;
        this.allowedPolicies = allowedPolicies;
        this.disallowedPolicies = disallowedPolicies;
        this.orphan = orphan;
        this.renewable = renewable;
        this.pathSuffix = pathSuffix;
        this.allowedEntityAliases = allowedEntityAliases;
        this.tokenBoundCidrs = tokenBoundCidrs;
        this.tokenExplicitMaxTtl = tokenExplicitMaxTtl;
        this.tokenNoDefaultPolicy = tokenNoDefaultPolicy;
        this.tokenNumUses = tokenNumUses;
        this.tokenPeriod = tokenPeriod;
        this.tokenType = tokenType;
    }

    /**
     * @return Token Role name
     */
    public String getName() {
        return name;
    }

    /**
     * @return List of allowed policies
     */
    public List<String> getAllowedPolicies() {
        return allowedPolicies;
    }

    /**
     * @return List of disallowed policies
     */
    public List<String> getDisallowedPolicies() {
        return disallowedPolicies;
    }

    /**
     * @return Is Roken Role orphan?
     */
    public Boolean getOrphan() {
        return orphan;
    }

    /**
     * @return Is Roken Role renewable?
     */
    public Boolean getRenewable() {
        return renewable;
    }

    /**
     * @return Path suffix
     */
    public String getPathSuffix() {
        return pathSuffix;
    }

    /**
     * @return List of allowed entity aliases
     */
    public List<String> getAllowedEntityAliases() {
        return allowedEntityAliases;
    }

    /**
     * @return Token bound CIDR blocks
     */
    public List<String> getTokenBoundCidrs() {
        return tokenBoundCidrs;
    }

    /**
     * @return Token explicit maximum TTL
     */
    public Integer getTokenExplicitMaxTtl() {
        return tokenExplicitMaxTtl;
    }

    /**
     * @return Token without default policy?
     */
    public Boolean getTokenNoDefaultPolicy() {
        return tokenNoDefaultPolicy;
    }

    /**
     * @return Token number of uses
     */
    public Integer getTokenNumUses() {
        return tokenNumUses;
    }

    /**
     * @return Token period
     */
    public Integer getTokenPeriod() {
        return tokenPeriod;
    }

    /**
     * @return Token type
     */
    public String getTokenType() {
        return tokenType;
    }
}
