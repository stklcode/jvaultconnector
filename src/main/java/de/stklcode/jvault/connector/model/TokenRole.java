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

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Vault Token Role metamodel.
 *
 * @param name                   Token Role name
 * @param allowedPolicies        List of allowed policies
 * @param allowedPoliciesGlob    List of allowed policy glob patterns
 * @param disallowedPolicies     List of disallowed policies
 * @param disallowedPoliciesGlob List of disallowed policy glob patterns
 * @param orphan                 Is Token Role orphan?
 * @param renewable              Is Token Role renewable?
 * @param pathSuffix             Path suffix
 * @param allowedEntityAliases   List of allowed entity aliases
 * @param tokenBoundCidrs        Token bound CIDR blocks
 * @param tokenExplicitMaxTtl    Token explicit maximum TTL
 * @param tokenNoDefaultPolicy   Token without default policy?
 * @param tokenNumUses           Token number of uses
 * @param tokenPeriod            Token period
 * @param tokenType              Token type
 * @author Stefan Kalscheuer
 * @since 0.9
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenRole(
    String name,
    List<String> allowedPolicies,
    List<String> allowedPoliciesGlob,
    List<String> disallowedPolicies,
    List<String> disallowedPoliciesGlob,
    Boolean orphan,
    Boolean renewable,
    String pathSuffix,
    List<String> allowedEntityAliases,
    List<String> tokenBoundCidrs,
    Long tokenExplicitMaxTtl,
    Boolean tokenNoDefaultPolicy,
    Integer tokenNumUses,
    Integer tokenPeriod,
    String tokenType
) implements Serializable {

    private TokenRole(final Builder builder) {
        this(
            builder.name,
            builder.allowedPolicies,
            builder.allowedPoliciesGlob,
            builder.disallowedPolicies,
            builder.disallowedPoliciesGlob,
            builder.orphan,
            builder.renewable,
            builder.pathSuffix,
            builder.allowedEntityAliases,
            builder.tokenBoundCidrs,
            builder.tokenExplicitMaxTtl,
            builder.tokenNoDefaultPolicy,
            builder.tokenNumUses,
            builder.tokenPeriod,
            builder.tokenType != null ? builder.tokenType.value() : null
        );
    }

    /**
     * Get {@link Builder} instance.
     *
     * @return Token Role Builder.
     */
    public static Builder builder() {
        return new Builder();
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
        private List<String> allowedPoliciesGlob;
        private List<String> disallowedPolicies;
        private List<String> disallowedPoliciesGlob;
        private Boolean orphan;
        private Boolean renewable;
        private String pathSuffix;
        private List<String> allowedEntityAliases;
        private List<String> tokenBoundCidrs;
        private Long tokenExplicitMaxTtl;
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
         * Add an allowed policy glob pattern.
         *
         * @param allowedPolicyGlob allowed policy glob pattern to add
         * @return self
         * @since 1.1
         */
        public Builder withAllowedPolicyGlob(final String allowedPolicyGlob) {
            if (allowedPolicyGlob != null) {
                if (this.allowedPoliciesGlob == null) {
                    this.allowedPoliciesGlob = new ArrayList<>();
                }
                this.allowedPoliciesGlob.add(allowedPolicyGlob);
            }
            return this;
        }

        /**
         * Add allowed policy glob patterns.
         *
         * @param allowedPoliciesGlob list of allowed policy glob patterns
         * @return self
         * @since 1.1
         */
        public Builder withAllowedPoliciesGlob(final List<String> allowedPoliciesGlob) {
            if (allowedPoliciesGlob != null) {
                if (this.allowedPoliciesGlob == null) {
                    this.allowedPoliciesGlob = new ArrayList<>();
                }
                this.allowedPoliciesGlob.addAll(allowedPoliciesGlob);
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
         * Add an allowed policy glob pattern.
         *
         * @param disallowedPolicyGlob disallowed policy glob pattern to add
         * @return self
         * @since 1.1
         */
        public Builder withDisallowedPolicyGlob(final String disallowedPolicyGlob) {
            if (disallowedPolicyGlob != null) {
                if (this.disallowedPoliciesGlob == null) {
                    this.disallowedPoliciesGlob = new ArrayList<>();
                }
                this.disallowedPoliciesGlob.add(disallowedPolicyGlob);
            }
            return this;
        }

        /**
         * Add disallowed policy glob patterns.
         *
         * @param disallowedPoliciesGlob list of disallowed policy glob patterns
         * @return self
         * @since 1.1
         */
        public Builder withDisallowedPoliciesGlob(final List<String> disallowedPoliciesGlob) {
            if (disallowedPoliciesGlob != null) {
                if (this.disallowedPoliciesGlob == null) {
                    this.disallowedPoliciesGlob = new ArrayList<>();
                }
                this.disallowedPoliciesGlob.addAll(disallowedPoliciesGlob);
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
        public Builder withTokenExplicitMaxTtl(final Long tokenExplicitMaxTtl) {
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
