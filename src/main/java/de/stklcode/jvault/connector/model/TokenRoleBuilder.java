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

import java.util.ArrayList;
import java.util.List;

/**
 * A builder for vault token roles.
 *
 * @author Stefan Kalscheuer
 * @since 0.9
 */
public final class TokenRoleBuilder {
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
    public TokenRoleBuilder forName(final String name) {
        this.name = name;
        return this;
    }

    /**
     * Add an allowed policy.
     *
     * @param allowedPolicy allowed policy to add
     * @return self
     */
    public TokenRoleBuilder withAllowedPolicy(final String allowedPolicy) {
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
    public TokenRoleBuilder withAllowedPolicies(final List<String> allowedPolicies) {
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
    public TokenRoleBuilder withDisallowedPolicy(final String disallowedPolicy) {
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
    public TokenRoleBuilder withDisallowedPolicies(final List<String> disallowedPolicies) {
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
    public TokenRoleBuilder orphan(final Boolean orphan) {
        this.orphan = orphan;
        return this;
    }

    /**
     * Set TRUE if the token role should be created renewable.
     *
     * @param renewable if TRUE, token role is created renewable
     * @return self
     */
    public TokenRoleBuilder renewable(final Boolean renewable) {
        this.renewable = renewable;
        return this;
    }

    /**
     * Set token role path suffix.
     *
     * @param pathSuffix path suffix to use
     * @return self
     */
    public TokenRoleBuilder withPathSuffix(final String pathSuffix) {
        this.pathSuffix = pathSuffix;
        return this;
    }

    /**
     * Add an allowed entity alias.
     *
     * @param allowedEntityAlias allowed entity alias to add
     * @return self
     */
    public TokenRoleBuilder withAllowedEntityAlias(final String allowedEntityAlias) {
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
    public TokenRoleBuilder withAllowedEntityAliases(final List<String> allowedEntityAliases) {
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
    public TokenRoleBuilder withTokenBoundCidr(final String tokenBoundCidr) {
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
    public TokenRoleBuilder withTokenBoundCidrs(final List<String> tokenBoundCidrs) {
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
    public TokenRoleBuilder withTokenExplicitMaxTtl(final Integer tokenExplicitMaxTtl) {
        this.tokenExplicitMaxTtl = tokenExplicitMaxTtl;
        return this;
    }

    /**
     * Set TRUE if the token role should be created renewable.
     *
     * @param tokenNoDefaultPolicy if TRUE, token is created without default policy.
     * @return self
     */
    public TokenRoleBuilder withTokenNoDefaultPolicy(final Boolean tokenNoDefaultPolicy) {
        this.tokenNoDefaultPolicy = tokenNoDefaultPolicy;
        return this;
    }

    /**
     * Set number of uses for tokens.
     *
     * @param tokenNumUses number of uses for associated tokens.
     * @return self
     */
    public TokenRoleBuilder withTokenNumUses(final Integer tokenNumUses) {
        this.tokenNumUses = tokenNumUses;
        return this;
    }

    /**
     * Set token period.
     *
     * @param tokenPeriod token period
     * @return self
     */
    public TokenRoleBuilder withTokenPeriod(final Integer tokenPeriod) {
        this.tokenPeriod = tokenPeriod;
        return this;
    }

    /**
     * Set token type.
     *
     * @param tokenType token type
     * @return self
     */
    public TokenRoleBuilder withTokenType(final Token.Type tokenType) {
        this.tokenType = tokenType;
        return this;
    }

    /**
     * Build the token based on given parameters.
     *
     * @return the token
     */
    public TokenRole build() {
        return new TokenRole(
                name,
                allowedPolicies,
                disallowedPolicies,
                orphan,
                renewable,
                pathSuffix,
                allowedEntityAliases,
                tokenBoundCidrs,
                tokenExplicitMaxTtl,
                tokenNoDefaultPolicy,
                tokenNumUses,
                tokenPeriod,
                tokenType != null ? tokenType.value() : null
        );
    }
}
