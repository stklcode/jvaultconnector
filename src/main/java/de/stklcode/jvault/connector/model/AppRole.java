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

import java.util.ArrayList;
import java.util.List;

/**
 * Vault AppRole role metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppRole {
    /**
     * Get {@link Builder} instance.
     *
     * @param name Role name.
     * @return AppRole Builder.
     * @since 0.8
     */
    public static Builder builder(final String name) {
        return new Builder(name);
    }

    @JsonProperty("role_name")
    private String name;

    @JsonProperty("role_id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    @JsonProperty("bind_secret_id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean bindSecretId;

    private List<String> secretIdBoundCidrs;

    @JsonProperty("secret_id_num_uses")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer secretIdNumUses;

    @JsonProperty("secret_id_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer secretIdTtl;

    @JsonProperty("enable_local_secret_ids")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean enableLocalSecretIds;

    @JsonProperty("token_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenTtl;

    @JsonProperty("token_max_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer tokenMaxTtl;

    private List<String> tokenPolicies;

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
     * Construct empty {@link AppRole} object.
     */
    public AppRole() {
    }

    /**
     * Construct complete {@link AppRole} object.
     * <p>
     * This constructor is used for transition from {@code bound_cidr_list} to {@code secret_id_bound_cidrs} only.
     *
     * @param name                 Role name (required)
     * @param id                   Role ID (optional)
     * @param bindSecretId         Bind secret ID (optional)
     * @param secretIdBoundCidrs   Whitelist of subnets in CIDR notation (optional)
     * @param secretIdNumUses      Maximum number of uses per secret (optional)
     * @param secretIdTtl          Maximum TTL in seconds for secrets (optional)
     * @param enableLocalSecretIds Enable local secret IDs (optional)
     * @param tokenTtl             Token TTL in seconds (optional)
     * @param tokenMaxTtl          Maximum token TTL in seconds, including renewals (optional)
     * @param tokenPolicies        List of token policies (optional)
     * @param tokenBoundCidrs      Whitelist of subnets in CIDR notation for associated tokens (optional)
     * @param tokenExplicitMaxTtl  Explicit maximum TTL for associated tokens (optional)
     * @param tokenNoDefaultPolicy Enable or disable default policy for associated tokens (optional)
     * @param tokenNumUses         Number of uses for tokens (optional)
     * @param tokenPeriod          Duration in seconds, if set the token is a periodic token (optional)
     * @param tokenType            Token type (optional)
     * @deprecated As of 0.9 in favor of {@link #builder(String)}. Will be removed with next major release.
     */
    @Deprecated
    AppRole(final String name, final String id, final Boolean bindSecretId, final List<String> secretIdBoundCidrs,
            final Integer secretIdNumUses, final Integer secretIdTtl, final Boolean enableLocalSecretIds,
            final Integer tokenTtl, final Integer tokenMaxTtl, final List<String> tokenPolicies,
            final List<String> tokenBoundCidrs, final Integer tokenExplicitMaxTtl, final Boolean tokenNoDefaultPolicy,
            final Integer tokenNumUses, final Integer tokenPeriod, final String tokenType) {
        this.name = name;
        this.id = id;
        this.bindSecretId = bindSecretId;
        this.secretIdBoundCidrs = secretIdBoundCidrs;
        this.tokenPolicies = tokenPolicies;
        this.secretIdNumUses = secretIdNumUses;
        this.secretIdTtl = secretIdTtl;
        this.enableLocalSecretIds = enableLocalSecretIds;
        this.tokenTtl = tokenTtl;
        this.tokenMaxTtl = tokenMaxTtl;
        this.tokenBoundCidrs = tokenBoundCidrs;
        this.tokenExplicitMaxTtl = tokenExplicitMaxTtl;
        this.tokenNoDefaultPolicy = tokenNoDefaultPolicy;
        this.tokenNumUses = tokenNumUses;
        this.tokenPeriod = tokenPeriod;
        this.tokenType = tokenType;
    }

    /**
     * Construct {@link AppRole} object from {@link AppRole.Builder}.
     *
     * @param builder AppRole builder.
     */
    public AppRole(final Builder builder) {
        this.name = builder.name;
        this.id = builder.id;
        this.bindSecretId = builder.bindSecretId;
        this.secretIdBoundCidrs = builder.secretIdBoundCidrs;
        this.secretIdNumUses = builder.secretIdNumUses;
        this.secretIdTtl = builder.secretIdTtl;
        this.enableLocalSecretIds = builder.enableLocalSecretIds;
        this.tokenTtl = builder.tokenTtl;
        this.tokenMaxTtl = builder.tokenMaxTtl;
        this.tokenPolicies = builder.tokenPolicies;
        this.tokenBoundCidrs = builder.tokenBoundCidrs;
        this.tokenExplicitMaxTtl = builder.tokenExplicitMaxTtl;
        this.tokenNoDefaultPolicy = builder.tokenNoDefaultPolicy;
        this.tokenNumUses = builder.tokenNumUses;
        this.tokenPeriod = builder.tokenPeriod;
        this.tokenType = builder.tokenType != null ? builder.tokenType.value() : null;
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
     * @return list of bound CIDR subnets of associated tokens
     * @since 0.9
     */
    public List<String> getTokenBoundCidrs() {
        return tokenBoundCidrs;
    }

    /**
     * @param boundCidrList list of subnets in CIDR notation to bind role to
     * @since 0.9
     */
    @JsonSetter("token_bound_cidrs")
    public void setBoundCidrs(final List<String> boundCidrList) {
        this.tokenBoundCidrs = boundCidrList;
    }

    /**
     * @return list of subnets in CIDR notation as comma-separated {@link String}
     * @since 0.9
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
     * @return list of bound CIDR subnets
     * @since 0.8 replaces {@code getBoundCidrList()}
     */
    public List<String> getSecretIdBoundCidrs() {
        return secretIdBoundCidrs;
    }

    /**
     * @param secretIdBoundCidrs List of subnets in CIDR notation to bind secrets of this role to.
     * @since 0.8 replaces {@code setBoundCidrList(List)}
     */
    @JsonSetter("secret_id_bound_cidrs")
    public void setSecretIdBoundCidrs(final List<String> secretIdBoundCidrs) {
        this.secretIdBoundCidrs = secretIdBoundCidrs;
    }

    /**
     * @return List of subnets in CIDR notation as comma-separated {@link String}
     * @since 0.8 replaces {@code getBoundCidrListString()} ()}
     */
    @JsonGetter("secret_id_bound_cidrs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getSecretIdBoundCidrsString() {
        if (secretIdBoundCidrs == null || secretIdBoundCidrs.isEmpty()) {
            return "";
        }
        return String.join(",", secretIdBoundCidrs);
    }

    /**
     * @return list of token policies
     * @since 0.9
     */
    public List<String> getTokenPolicies() {
        return tokenPolicies;
    }

    /**
     * @return list of token policies
     * @deprecated Use {@link #getTokenPolicies()} instead.
     */
    @Deprecated
    @JsonIgnore
    public List<String> getPolicies() {
        return getTokenPolicies();
    }

    /**
     * @param tokenPolicies list of token policies
     * @since 0.9
     */
    @JsonSetter("token_policies")
    public void setTokenPolicies(final List<String> tokenPolicies) {
        this.tokenPolicies = tokenPolicies;
    }

    /**
     * @param policies list of policies
     * @deprecated Use {@link #setTokenPolicies(List)} instead.
     */
    @Deprecated
    @JsonIgnore
    public void setPolicies(final List<String> policies) {
        setTokenPolicies(policies);
    }

    /**
     * @return list of policies as comma-separated {@link String}
     * @since 0.9
     */
    @JsonGetter("token_policies")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getTokenPoliciesString() {
        if (tokenPolicies == null || tokenPolicies.isEmpty()) {
            return "";
        }
        return String.join(",", tokenPolicies);
    }

    /**
     * @return list of policies as comma-separated {@link String}
     * @deprecated Use {@link #getTokenPoliciesString()} instead.
     */
    @Deprecated
    @JsonIgnore
    public String getPoliciesString() {
        return getTokenPoliciesString();
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
     * @return Enable local secret IDs?
     * @since 0.9
     */
    public Boolean getEnableLocalSecretIds() {
        return enableLocalSecretIds;
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
     * @return explicit maximum token TTL in seconds, including renewals
     * @since 0.9
     */
    public Integer getTokenExplicitMaxTtl() {
        return tokenExplicitMaxTtl;
    }

    /**
     * @return enable default policy for token?
     * @since 0.9
     */
    public Boolean getTokenNoDefaultPolicy() {
        return tokenNoDefaultPolicy;
    }

    /**
     * @return number of uses for token
     * @since 0.9
     */
    public Integer getTokenNumUses() {
        return tokenNumUses;
    }

    /**
     * @return duration in seconds, if specified
     * @since 0.9
     */
    public Integer getTokenPeriod() {
        return tokenPeriod;
    }

    /**
     * @return duration in seconds, if specified
     * @deprecated Use {@link #getTokenPeriod()} instead.
     */
    @Deprecated
    @JsonIgnore
    public Integer getPeriod() {
        return getTokenPeriod();
    }

    /**
     * @return duration in seconds, if specified
     * @since 0.9
     */
    public String getTokenType() {
        return tokenType;
    }


    /**
     * A builder for vault AppRole roles..
     *
     * @author Stefan Kalscheuer
     * @since 0.4.0
     * @since 0.9 Moved into subclass of {@link AppRole}.
     */
    public static final class Builder {
        private String name;
        private String id;
        private Boolean bindSecretId;
        private List<String> secretIdBoundCidrs;
        private List<String> tokenPolicies;
        private Integer secretIdNumUses;
        private Integer secretIdTtl;
        private Boolean enableLocalSecretIds;
        private Integer tokenTtl;
        private Integer tokenMaxTtl;
        private List<String> tokenBoundCidrs;
        private Integer tokenExplicitMaxTtl;
        private Boolean tokenNoDefaultPolicy;
        private Integer tokenNumUses;
        private Integer tokenPeriod;
        private Token.Type tokenType;

        /**
         * Construct {@link Builder} with only the role name set.
         *
         * @param name Role name
         */
        public Builder(final String name) {
            this.name = name;
        }

        /**
         * Add role name.
         *
         * @param name Role name
         * @return self
         */
        public Builder withName(final String name) {
            this.name = name;
            return this;
        }

        /**
         * Add custom role ID. (optional)
         *
         * @param id the ID
         * @return self
         */
        public Builder withId(final String id) {
            this.id = id;
            return this;
        }

        /**
         * Set if role is bound to secret ID.
         *
         * @param bindSecretId the display name
         * @return self
         */
        public Builder withBindSecretID(final Boolean bindSecretId) {
            this.bindSecretId = bindSecretId;
            return this;
        }

        /**
         * Bind role to secret ID.
         * Convenience method for {@link #withBindSecretID(Boolean)}
         *
         * @return self
         */
        public Builder withBindSecretID() {
            return withBindSecretID(true);
        }

        /**
         * Do not bind role to secret ID.
         * Convenience method for {@link #withBindSecretID(Boolean)}
         *
         * @return self
         */
        public Builder withoutBindSecretID() {
            return withBindSecretID(false);
        }

        /**
         * Set bound CIDR blocks.
         *
         * @param secretIdBoundCidrs List of CIDR blocks which can perform login
         * @return self
         * @since 0.8 replaces {@code withBoundCidrList(List)}
         */
        public Builder withSecretIdBoundCidrs(final List<String> secretIdBoundCidrs) {
            if (this.secretIdBoundCidrs == null) {
                this.secretIdBoundCidrs = new ArrayList<>();
            }
            this.secretIdBoundCidrs.addAll(secretIdBoundCidrs);
            return this;
        }

        /**
         * Add a CIDR block to list of bound blocks for secret.
         *
         * @param secretBoundCidr the CIDR block
         * @return self
         * @since 0.9
         */
        public Builder withSecretBoundCidr(final String secretBoundCidr) {
            if (secretIdBoundCidrs == null) {
                secretIdBoundCidrs = new ArrayList<>();
            }
            secretIdBoundCidrs.add(secretBoundCidr);
            return this;
        }

        /**
         * Add given policies.
         *
         * @param tokenPolicies the token policies
         * @return self
         * @since 0.9
         */
        public Builder withTokenPolicies(final List<String> tokenPolicies) {
            if (this.tokenPolicies == null) {
                this.tokenPolicies = new ArrayList<>();
            }
            this.tokenPolicies.addAll(tokenPolicies);
            return this;
        }

        /**
         * Add given policies.
         *
         * @param policies the policies
         * @return self
         * @deprecated Use {@link #withTokenPolicies(List)} instead.
         */
        @Deprecated
        public Builder withPolicies(final List<String> policies) {
            return withTokenPolicies(policies);
        }

        /**
         * Add a single policy.
         *
         * @param tokenPolicy the token policy
         * @return self
         * @since 0.9
         */
        public Builder withTokenPolicy(final String tokenPolicy) {
            if (this.tokenPolicies == null) {
                this.tokenPolicies = new ArrayList<>();
            }
            tokenPolicies.add(tokenPolicy);
            return this;
        }

        /**
         * Add a single policy.
         *
         * @param policy the policy
         * @return self
         * @deprecated Use {@link #withTokenPolicy(String)} instead.
         */
        @Deprecated
        public Builder withPolicy(final String policy) {
            return withTokenPolicy(policy);
        }

        /**
         * Set number of uses for sectet IDs.
         *
         * @param secretIdNumUses the number of uses
         * @return self
         */
        public Builder withSecretIdNumUses(final Integer secretIdNumUses) {
            this.secretIdNumUses = secretIdNumUses;
            return this;
        }

        /**
         * Set default sectet ID TTL in seconds.
         *
         * @param secretIdTtl the TTL
         * @return self
         */
        public Builder withSecretIdTtl(final Integer secretIdTtl) {
            this.secretIdTtl = secretIdTtl;
            return this;
        }

        /**
         * Enable or disable local secret IDs.
         *
         * @param enableLocalSecretIds Enable local secret IDs?
         * @return self
         * @since 0.9
         */
        public Builder withEnableLocalSecretIds(final Boolean enableLocalSecretIds) {
            this.enableLocalSecretIds = enableLocalSecretIds;
            return this;
        }

        /**
         * Set default token TTL in seconds.
         *
         * @param tokenTtl the TTL
         * @return self
         */
        public Builder withTokenTtl(final Integer tokenTtl) {
            this.tokenTtl = tokenTtl;
            return this;
        }

        /**
         * Set maximum token TTL in seconds.
         *
         * @param tokenMaxTtl the TTL
         * @return self
         */
        public Builder withTokenMaxTtl(final Integer tokenMaxTtl) {
            this.tokenMaxTtl = tokenMaxTtl;
            return this;
        }

        /**
         * Set bound CIDR blocks for associated tokens.
         *
         * @param tokenBoundCidrs List of CIDR blocks which can perform login
         * @return self
         * @since 0.9
         */
        public Builder withTokenBoundCidrs(final List<String> tokenBoundCidrs) {
            if (this.tokenBoundCidrs == null) {
                this.tokenBoundCidrs = new ArrayList<>();
            }
            this.tokenBoundCidrs.addAll(tokenBoundCidrs);
            return this;
        }

        /**
         * Add a CIDR block to list of bound blocks for token.
         *
         * @param tokenBoundCidr the CIDR block
         * @return self
         * @since 0.9
         */
        public Builder withTokenBoundCidr(final String tokenBoundCidr) {
            if (tokenBoundCidrs == null) {
                tokenBoundCidrs = new ArrayList<>();
            }
            tokenBoundCidrs.add(tokenBoundCidr);
            return this;
        }

        /**
         * Set explicit maximum token TTL in seconds.
         *
         * @param tokenExplicitMaxTtl the TTL
         * @return self
         */
        public Builder withTokenExplicitMaxTtl(final Integer tokenExplicitMaxTtl) {
            this.tokenExplicitMaxTtl = tokenExplicitMaxTtl;
            return this;
        }

        /**
         * Enable or disable default policy for generated token.
         *
         * @param tokenNoDefaultPolicy Enable default policy for token?
         * @return self
         * @since 0.9
         */
        public Builder withTokenNoDefaultPolicy(final Boolean tokenNoDefaultPolicy) {
            this.tokenNoDefaultPolicy = tokenNoDefaultPolicy;
            return this;
        }

        /**
         * Set number of uses for generated tokens.
         *
         * @param tokenNumUses number of uses for tokens
         * @return self
         * @since 0.9
         */
        public Builder withTokenNumUses(final Integer tokenNumUses) {
            this.tokenNumUses = tokenNumUses;
            return this;
        }

        /**
         * Set renewal period for generated token in seconds.
         *
         * @param tokenPeriod period in seconds
         * @return self
         * @since 0.9
         */
        public Builder withTokenPeriod(final Integer tokenPeriod) {
            this.tokenPeriod = tokenPeriod;
            return this;
        }

        /**
         * Set renewal period for generated token in seconds.
         *
         * @param tokenPeriod period in seconds
         * @return self
         * @since 0.9
         * @deprecated Use {@link #withTokenPeriod(Integer)} instead.
         */
        @Deprecated
        public Builder wit0hTokenPeriod(final Integer tokenPeriod) {
            return withTokenPeriod(tokenPeriod);
        }

        /**
         * Set renewal period for generated token in seconds.
         *
         * @param period period in seconds
         * @return self
         * @deprecated Use {@link #withTokenPeriod(Integer)} instead.
         */
        @Deprecated
        public Builder withPeriod(final Integer period) {
            return withTokenPeriod(period);
        }

        /**
         * Set type of generated token.
         *
         * @param tokenType token type
         * @return self
         * @since 0.9
         */
        public Builder withTokenType(final Token.Type tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        /**
         * Build the AppRole role based on given parameters.
         *
         * @return the role
         */
        public AppRole build() {
            return new AppRole(this);
        }
    }
}
