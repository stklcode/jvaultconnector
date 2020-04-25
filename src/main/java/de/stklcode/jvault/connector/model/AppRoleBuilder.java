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
 * A builder for vault AppRole roles..
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @deprecated As of 0.9 in favor of {@link AppRole.Builder}.
 */
@Deprecated
public final class AppRoleBuilder {
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
     * Construct {@link AppRoleBuilder} with only the role name set.
     *
     * @param name Role name
     */
    public AppRoleBuilder(final String name) {
        this.name = name;
    }

    /**
     * Add custom role ID. (optional)
     *
     * @param id the ID
     * @return self
     */
    public AppRoleBuilder withId(final String id) {
        this.id = id;
        return this;
    }

    /**
     * Set if role is bound to secret ID.
     *
     * @param bindSecretId the display name
     * @return self
     */
    public AppRoleBuilder withBindSecretID(final Boolean bindSecretId) {
        this.bindSecretId = bindSecretId;
        return this;
    }

    /**
     * Bind role to secret ID.
     * Convenience method for {@link #withBindSecretID(Boolean)}
     *
     * @return self
     */
    public AppRoleBuilder withBindSecretID() {
        return withBindSecretID(true);
    }

    /**
     * Do not bind role to secret ID.
     * Convenience method for {@link #withBindSecretID(Boolean)}
     *
     * @return self
     */
    public AppRoleBuilder withoutBindSecretID() {
        return withBindSecretID(false);
    }

    /**
     * Set bound CIDR blocks.
     *
     * @param secretIdBoundCidrs List of CIDR blocks which can perform login
     * @return self
     * @since 0.8 replaces {@code withBoundCidrList(List)}
     */
    public AppRoleBuilder withSecretIdBoundCidrs(final List<String> secretIdBoundCidrs) {
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
    public AppRoleBuilder withSecretBoundCidr(final String secretBoundCidr) {
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
    public AppRoleBuilder withTokenPolicies(final List<String> tokenPolicies) {
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
    public AppRoleBuilder withPolicies(final List<String> policies) {
        return withTokenPolicies(policies);
    }

    /**
     * Add a single policy.
     *
     * @param tokenPolicy the token policy
     * @return self
     * @since 0.9
     */
    public AppRoleBuilder withTokenPolicy(final String tokenPolicy) {
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
    public AppRoleBuilder withPolicy(final String policy) {
        return withTokenPolicy(policy);
    }

    /**
     * Set number of uses for secret IDs.
     *
     * @param secretIdNumUses the number of uses
     * @return self
     */
    public AppRoleBuilder withSecretIdNumUses(final Integer secretIdNumUses) {
        this.secretIdNumUses = secretIdNumUses;
        return this;
    }

    /**
     * Set default secret ID TTL in seconds.
     *
     * @param secretIdTtl the TTL
     * @return self
     */
    public AppRoleBuilder withSecretIdTtl(final Integer secretIdTtl) {
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
    public AppRoleBuilder withEnableLocalSecretIds(final Boolean enableLocalSecretIds) {
        this.enableLocalSecretIds = enableLocalSecretIds;
        return this;
    }

    /**
     * Set default token TTL in seconds.
     *
     * @param tokenTtl the TTL
     * @return self
     */
    public AppRoleBuilder withTokenTtl(final Integer tokenTtl) {
        this.tokenTtl = tokenTtl;
        return this;
    }

    /**
     * Set maximum token TTL in seconds.
     *
     * @param tokenMaxTtl the TTL
     * @return self
     */
    public AppRoleBuilder withTokenMaxTtl(final Integer tokenMaxTtl) {
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
    public AppRoleBuilder withTokenBoundCidrs(final List<String> tokenBoundCidrs) {
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
    public AppRoleBuilder withTokenBoundCidr(final String tokenBoundCidr) {
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
    public AppRoleBuilder withTokenExplicitMaxTtl(final Integer tokenExplicitMaxTtl) {
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
    public AppRoleBuilder withTokenNoDefaultPolicy(final Boolean tokenNoDefaultPolicy) {
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
    public AppRoleBuilder withTokenNumUses(final Integer tokenNumUses) {
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
    public AppRoleBuilder wit0hTokenPeriod(final Integer tokenPeriod) {
        this.tokenPeriod = tokenPeriod;
        return this;
    }

    /**
     * Set renewal period for generated token in seconds.
     *
     * @param period period in seconds
     * @return self
     * @deprecated Use {@link #wit0hTokenPeriod(Integer)} instead.
     */
    @Deprecated
    public AppRoleBuilder withPeriod(final Integer period) {
        return wit0hTokenPeriod(period);
    }

    /**
     * Set type of generated token.
     *
     * @param tokenType token type
     * @return self
     * @since 0.9
     */
    public AppRoleBuilder withTokenType(final Token.Type tokenType) {
        this.tokenType = tokenType;
        return this;
    }

    /**
     * Build the AppRole role based on given parameters.
     *
     * @return the role
     */
    public AppRole build() {
        return new AppRole(
                name,
                id,
                bindSecretId,
                secretIdBoundCidrs,
                secretIdNumUses,
                secretIdTtl,
                enableLocalSecretIds,
                tokenTtl,
                tokenMaxTtl,
                tokenPolicies,
                tokenBoundCidrs,
                tokenExplicitMaxTtl,
                tokenNoDefaultPolicy,
                tokenNumUses,
                tokenPeriod,
                tokenType != null ? tokenType.value() : null
        );
    }
}
