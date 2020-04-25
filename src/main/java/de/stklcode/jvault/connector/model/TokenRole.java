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

import java.util.ArrayList;
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
     * Get {@link Builder} instance.
     *
     * @return Token Role Builder.
     */
    public static Builder builder() {
        return new Builder();
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
     * Construct empty {@link TokenRole} object.
     */
    public TokenRole() {
    }

    public TokenRole(final Builder builder) {
        this.name = builder.name;
        this.allowedPolicies = builder.allowedPolicies;
        this.disallowedPolicies = builder.disallowedPolicies;
        this.orphan = builder.orphan;
        this.renewable = builder.renewable;
        this.pathSuffix = builder.pathSuffix;
        this.allowedEntityAliases = builder.allowedEntityAliases;
        this.tokenBoundCidrs = builder.tokenBoundCidrs;
        this.tokenExplicitMaxTtl = builder.tokenExplicitMaxTtl;
        this.tokenNoDefaultPolicy = builder.tokenNoDefaultPolicy;
        this.tokenNumUses = builder.tokenNumUses;
        this.tokenPeriod = builder.tokenPeriod;
        this.tokenType = builder.tokenType != null ? builder.tokenType.value() : null;
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
     * @return Is Token Role orphan?
     */
    public Boolean getOrphan() {
        return orphan;
    }

    /**
     * @return Is Token Role renewable?
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

    /**
     * A builder for vault token roles.
     *
     * @author Stefan Kalscheuer
     * @since 0.9
     */
    public static final class Builder {
        private String name;
        private List<String> allowedPolicies;
        private List<String> disallowedPolicies;
        private Boolean orphan;
        private Boolean renewable;
        private String pathSuffix;
        private List<String> allowedEntityAliases;
        private List<String> tokenBoundCidrs;
        private Integer tokenExplicitMaxTtl;
        private Boolean tokenNoDefaultPolicy;
        private Integer tokenNumUses;
        private Integer tokenPeriod;
        private Token.Type tokenType;

        /**
         * Add token role name.
         *
         * @param name role name
         * @return self
         */
        public Builder forName(final String name) {
            this.name = name;
            return this;
        }

        /**
         * Add an allowed policy.
         *
         * @param allowedPolicy allowed policy to add
         * @return self
         */
        public Builder withAllowedPolicy(final String allowedPolicy) {
            if (allowedPolicy != null) {
                if (this.allowedPolicies == null) {
                    this.allowedPolicies = new ArrayList<>();
                }
                this.allowedPolicies.add(allowedPolicy);
            }
            return this;
        }

        /**
         * Add allowed policies.
         *
         * @param allowedPolicies list of allowed policies
         * @return self
         */
        public Builder withAllowedPolicies(final List<String> allowedPolicies) {
            if (allowedPolicies != null) {
                if (this.allowedPolicies == null) {
                    this.allowedPolicies = new ArrayList<>();
                }
                this.allowedPolicies.addAll(allowedPolicies);
            }
            return this;
        }

        /**
         * Add a disallowed policy.
         *
         * @param disallowedPolicy disallowed policy to add
         * @return self
         */
        public Builder withDisallowedPolicy(final String disallowedPolicy) {
            if (disallowedPolicy != null) {
                if (this.disallowedPolicies == null) {
                    this.disallowedPolicies = new ArrayList<>();
                }
                this.disallowedPolicies.add(disallowedPolicy);
            }
            return this;
        }

        /**
         * Add disallowed policies.
         *
         * @param disallowedPolicies list of disallowed policies
         * @return self
         */
        public Builder withDisallowedPolicies(final List<String> disallowedPolicies) {
            if (disallowedPolicies != null) {
                if (this.disallowedPolicies == null) {
                    this.disallowedPolicies = new ArrayList<>();
                }
                this.disallowedPolicies.addAll(disallowedPolicies);
            }
            return this;
        }

        /**
         * Set TRUE if the token role should be created orphan.
         *
         * @param orphan if TRUE, token role is created as orphan
         * @return self
         */
        public Builder orphan(final Boolean orphan) {
            this.orphan = orphan;
            return this;
        }

        /**
         * Set TRUE if the token role should be created renewable.
         *
         * @param renewable if TRUE, token role is created renewable
         * @return self
         */
        public Builder renewable(final Boolean renewable) {
            this.renewable = renewable;
            return this;
        }

        /**
         * Set token role path suffix.
         *
         * @param pathSuffix path suffix to use
         * @return self
         */
        public Builder withPathSuffix(final String pathSuffix) {
            this.pathSuffix = pathSuffix;
            return this;
        }

        /**
         * Add an allowed entity alias.
         *
         * @param allowedEntityAlias allowed entity alias to add
         * @return self
         */
        public Builder withAllowedEntityAlias(final String allowedEntityAlias) {
            if (allowedEntityAlias != null) {
                if (this.allowedEntityAliases == null) {
                    this.allowedEntityAliases = new ArrayList<>();
                }
                this.allowedEntityAliases.add(allowedEntityAlias);
            }
            return this;
        }

        /**
         * Add allowed entity aliases.
         *
         * @param allowedEntityAliases list of allowed entity aliases to add
         * @return self
         */
        public Builder withAllowedEntityAliases(final List<String> allowedEntityAliases) {
            if (allowedEntityAliases != null) {
                if (this.allowedEntityAliases == null) {
                    this.allowedEntityAliases = new ArrayList<>();
                }
                this.allowedEntityAliases.addAll(allowedEntityAliases);
            }
            return this;
        }

        /**
         * Add a single bound CIDR.
         *
         * @param tokenBoundCidr bound CIDR to add
         * @return self
         */
        public Builder withTokenBoundCidr(final String tokenBoundCidr) {
            if (tokenBoundCidr != null) {
                if (this.tokenBoundCidrs == null) {
                    this.tokenBoundCidrs = new ArrayList<>();
                }
                this.tokenBoundCidrs.add(tokenBoundCidr);
            }
            return this;
        }

        /**
         * Add a list of bound CIDRs.
         *
         * @param tokenBoundCidrs list of bound CIDRs to add
         * @return self
         */
        public Builder withTokenBoundCidrs(final List<String> tokenBoundCidrs) {
            if (tokenBoundCidrs != null) {
                if (this.tokenBoundCidrs == null) {
                    this.tokenBoundCidrs = new ArrayList<>();
                }
                this.tokenBoundCidrs.addAll(tokenBoundCidrs);
            }
            return this;
        }

        /**
         * Set explicit max. TTL for token.
         *
         * @param tokenExplicitMaxTtl explicit maximum TTL
         * @return self
         */
        public Builder withTokenExplicitMaxTtl(final Integer tokenExplicitMaxTtl) {
            this.tokenExplicitMaxTtl = tokenExplicitMaxTtl;
            return this;
        }

        /**
         * Set TRUE if the token role should be created renewable.
         *
         * @param tokenNoDefaultPolicy if TRUE, token is created without default policy.
         * @return self
         */
        public Builder withTokenNoDefaultPolicy(final Boolean tokenNoDefaultPolicy) {
            this.tokenNoDefaultPolicy = tokenNoDefaultPolicy;
            return this;
        }

        /**
         * Set number of uses for tokens.
         *
         * @param tokenNumUses number of uses for associated tokens.
         * @return self
         */
        public Builder withTokenNumUses(final Integer tokenNumUses) {
            this.tokenNumUses = tokenNumUses;
            return this;
        }

        /**
         * Set token period.
         *
         * @param tokenPeriod token period
         * @return self
         */
        public Builder withTokenPeriod(final Integer tokenPeriod) {
            this.tokenPeriod = tokenPeriod;
            return this;
        }

        /**
         * Set token type.
         *
         * @param tokenType token type
         * @return self
         */
        public Builder withTokenType(final Token.Type tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        /**
         * Build the token based on given parameters.
         *
         * @return the token
         */
        public TokenRole build() {
            return new TokenRole(this);
        }
    }
}
