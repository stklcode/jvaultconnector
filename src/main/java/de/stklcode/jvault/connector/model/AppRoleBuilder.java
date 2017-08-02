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

import java.util.ArrayList;
import java.util.List;

/**
 * A builder for vault AppRole roles..
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
public final class AppRoleBuilder {
    private String name;
    private String id;
    private Boolean bindSecretId;
    private List<String> boundCidrList;
    private List<String> policies;
    private Integer secretIdNumUses;
    private Integer secretIdTtl;
    private Integer tokenTtl;
    private Integer tokenMaxTtl;
    private Integer period;

    public AppRoleBuilder(final String name) {
        this.name = name;
    }

    /**
     * Add custom role ID (optional)
     *
     * @param id the ID
     * @return self
     */
    public AppRoleBuilder withId(final String id) {
        this.id = id;
        return this;
    }

    /**
     * Set if role is bound to secret ID
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
     * @param boundCidrList List of CIDR blocks which can perform login
     * @return self
     */
    public AppRoleBuilder withBoundCidrList(final List<String> boundCidrList) {
        this.boundCidrList = boundCidrList;
        return this;
    }

    /**
     * Add a CIDR block to list of bound blocks.
     *
     * @param cidrBlock the CIDR block
     * @return self
     */
    public AppRoleBuilder withCidrBlock(final String cidrBlock) {
        if (boundCidrList == null)
            boundCidrList = new ArrayList<>();
        boundCidrList.add(cidrBlock);
        return this;
    }

    /**
     * Add given policies
     *
     * @param policies the policies
     * @return self
     */
    public AppRoleBuilder withPolicies(final List<String> policies) {
        if (this.policies == null)
            this.policies = new ArrayList<>();
        this.policies.addAll(policies);
        return this;
    }

    /**
     * Add a single policy.
     *
     * @param policy the policy
     * @return self
     */
    public AppRoleBuilder withPolicy(final String policy) {
        if (this.policies == null)
            this.policies = new ArrayList<>();
        policies.add(policy);
        return this;
    }

    /**
     * Set number of uses for sectet IDs.
     *
     * @param secredIdNumUses the number of uses
     * @return self
     */
    public AppRoleBuilder withSecretIdNumUses(final Integer secredIdNumUses) {
        this.secretIdNumUses = secredIdNumUses;
        return this;
    }

    /**
     * Set default sectet ID TTL in seconds.
     *
     * @param secredIdTtl the TTL
     * @return self
     */
    public AppRoleBuilder withSecretIdTtl(final Integer secredIdTtl) {
        this.secretIdTtl = secredIdTtl;
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
     * Set renewal period for generated token in seconds.
     *
     * @param period period in seconds
     * @return self
     */
    public AppRoleBuilder withPeriod(final Integer period) {
        this.period = period;
        return this;
    }


    /**
     * Build the AppRole role based on given parameters.
     *
     * @return the role
     */
    public AppRole build() {
        return new AppRole(name,
                id,
                bindSecretId,
                boundCidrList,
                policies,
                secretIdNumUses,
                secretIdTtl,
                tokenTtl,
                tokenMaxTtl,
                period);
    }
}
