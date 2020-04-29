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

import java.util.*;

/**
 * A builder for vault tokens.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @deprecated As of 0.9 in favor of {@link Token.Builder}.
 */
@Deprecated
public final class TokenBuilder {
    private String id;
    private Token.Type type;
    private String displayName;
    private Boolean noParent;
    private Boolean noDefaultPolicy;
    private Integer ttl;
    private Integer numUses;
    private List<String> policies;
    private Map<String, String> meta;
    private Boolean renewable;

    /**
     * Add token ID. (optional)
     *
     * @param id the ID
     * @return self
     */
    public TokenBuilder withId(final String id) {
        this.id = id;
        return this;
    }

    /**
     * Specify token type.
     *
     * @param type the type
     * @return self
     * @since 0.9
     */
    public TokenBuilder withType(final Token.Type type) {
        this.type = type;
        return this;
    }

    /**
     * Add display name.
     *
     * @param displayName the display name
     * @return self
     */
    public TokenBuilder withDisplayName(final String displayName) {
        this.displayName = displayName;
        return this;
    }

    /**
     * Set desired time to live.
     *
     * @param ttl the ttl
     * @return self
     */
    public TokenBuilder withTtl(final Integer ttl) {
        this.ttl = ttl;
        return this;
    }

    /**
     * Set desired number of uses.
     *
     * @param numUses the number of uses
     * @return self
     */
    public TokenBuilder withNumUses(final Integer numUses) {
        this.numUses = numUses;
        return this;
    }

    /**
     * Set TRUE if the token should be created without parent.
     *
     * @param noParent if TRUE, token is created as orphan
     * @return self
     */
    public TokenBuilder withNoParent(final boolean noParent) {
        this.noParent = noParent;
        return this;
    }

    /**
     * Create token without parent.
     * Convenience method for withNoParent()
     *
     * @return self
     */
    public TokenBuilder asOrphan() {
        return withNoParent(true);
    }

    /**
     * Create token with parent.
     * Convenience method for withNoParent()
     *
     * @return self
     */
    public TokenBuilder withParent() {
        return withNoParent(false);
    }

    /**
     * Set TRUE if the default policy should not be part of this token.
     *
     * @param noDefaultPolicy if TRUE, default policy is not attached
     * @return self
     */
    public TokenBuilder withNoDefaultPolicy(final boolean noDefaultPolicy) {
        this.noDefaultPolicy = noDefaultPolicy;
        return this;
    }

    /**
     * Attach default policy to token.
     * Convenience method for withNoDefaultPolicy()
     *
     * @return self
     */
    public TokenBuilder withDefaultPolicy() {
        return withNoDefaultPolicy(false);
    }

    /**
     * Do not attach default policy to token.
     * Convenience method for withNoDefaultPolicy()
     *
     * @return self
     */
    public TokenBuilder withoutDefaultPolicy() {
        return withNoDefaultPolicy(true);
    }

    /**
     * Add given policies.
     *
     * @param policies the policies
     * @return self
     * @since 0.5.0
     */
    public TokenBuilder withPolicies(final String... policies) {
        return withPolicies(Arrays.asList(policies));
    }

    /**
     * Add given policies.
     *
     * @param policies the policies
     * @return self
     */
    public TokenBuilder withPolicies(final List<String> policies) {
        if (this.policies == null) {
            this.policies = new ArrayList<>();
        }
        this.policies.addAll(policies);
        return this;
    }

    /**
     * Add a single policy.
     *
     * @param policy the policy
     * @return self
     */
    public TokenBuilder withPolicy(final String policy) {
        if (this.policies == null) {
            this.policies = new ArrayList<>();
        }
        policies.add(policy);
        return this;
    }

    /**
     * Add meta data.
     *
     * @param meta the metadata
     * @return self
     */
    public TokenBuilder withMeta(final Map<String, String> meta) {
        if (this.meta == null) {
            this.meta = new HashMap<>();
        }
        this.meta.putAll(meta);
        return this;
    }

    /**
     * Add meta data.
     *
     * @param key   the key
     * @param value the value
     * @return self
     */
    public TokenBuilder withMeta(final String key, final String value) {
        if (this.meta == null) {
            this.meta = new HashMap<>();
        }
        this.meta.put(key, value);
        return this;
    }

    /**
     * Set if token is renewable.
     *
     * @param renewable TRUE, if renewable
     * @return self
     */
    public TokenBuilder withRenewable(final Boolean renewable) {
        this.renewable = renewable;
        return this;
    }

    /**
     * Set token to be renewable.
     * Convenience method for withRenewable()
     *
     * @return self
     */
    public TokenBuilder renewable() {
        return withRenewable(true);
    }

    /**
     * Set token to be not renewable.
     * Convenience method for withRenewable()
     *
     * @return self
     */
    public TokenBuilder notRenewable() {
        return withRenewable(false);
    }

    /**
     * Build the token based on given parameters.
     *
     * @return the token
     */
    public Token build() {
        return new Token(id,
                type != null ? type.value() : null,
                displayName,
                noParent,
                noDefaultPolicy,
                ttl,
                numUses,
                policies,
                meta,
                renewable);
    }
}
