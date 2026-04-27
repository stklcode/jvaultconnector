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
import java.util.*;

/**
 * Vault Token metamodel.
 *
 * @param id              Token ID
 * @param type            Token type
 * @param displayName     Token display name
 * @param noParent        Token has no parent
 * @param noDefaultPolicy Token has no default policy
 * @param ttl             Time-to-live in seconds
 * @param explicitMaxTtl  Explicit maximum time-to-live in seconds
 * @param numUses         Number of uses
 * @param policies        List of policies
 * @param meta            Metadata
 * @param renewable       Token is renewable
 * @param period          Token period
 * @param entityAlias     Token entity alias
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Token(
    String id,
    String type,
    String displayName,
    Boolean noParent,
    Boolean noDefaultPolicy,
    Long ttl,
    Long explicitMaxTtl,
    Integer numUses,
    List<String> policies,
    Map<String, String> meta,
    Boolean renewable,
    Integer period,
    String entityAlias
) implements Serializable {

    /**
     * Construct {@link Token} object from {@link Builder}.
     *
     * @param builder Token builder.
     */
    private Token(final Builder builder) {
        this(
            builder.id,
            builder.type != null ? builder.type.value() : null,
            builder.displayName,
            builder.noParent,
            builder.noDefaultPolicy,
            builder.ttl,
            builder.explicitMaxTtl,
            builder.numUses,
            builder.policies,
            builder.meta,
            builder.renewable,
            builder.period,
            builder.entityAlias
        );
    }

    /**
     * Get {@link Builder} instance.
     *
     * @return Token Builder.
     * @since 0.8
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * Constants for token types.
     */
    public enum Type {
        DEFAULT("default"),
        BATCH("batch"),
        SERVICE("service"),
        DEFAULT_SERVICE("default-service"),
        DEFAULT_BATCH("default-batch");

        private final String value;

        Type(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }


    /**
     * A builder for vault tokens.
     *
     * @author Stefan Kalscheuer
     * @since 0.4.0
     * @since 0.9 Moved into subclass of {@link Token}.
     */
    public static final class Builder {
        private String id;
        private Type type;
        private String displayName;
        private Boolean noParent;
        private Boolean noDefaultPolicy;
        private Long ttl;
        private Long explicitMaxTtl;
        private Integer numUses;
        private List<String> policies;
        private Map<String, String> meta;
        private Boolean renewable;
        private Integer period;
        private String entityAlias;

        /**
         * Add token ID. (optional)
         *
         * @param id the ID
         * @return self
         */
        public Builder withId(final String id) {
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
        public Builder withType(final Token.Type type) {
            this.type = type;
            return this;
        }

        /**
         * Add display name.
         *
         * @param displayName the display name
         * @return self
         */
        public Builder withDisplayName(final String displayName) {
            this.displayName = displayName;
            return this;
        }

        /**
         * Set desired time to live.
         *
         * @param ttl the ttl
         * @return self
         */
        public Builder withTtl(final Long ttl) {
            this.ttl = ttl;
            return this;
        }

        /**
         * Set desired explicit maximum time to live.
         *
         * @param explicitMaxTtl the explicit max. TTL
         * @return self
         */
        public Builder withExplicitMaxTtl(final Long explicitMaxTtl) {
            this.explicitMaxTtl = explicitMaxTtl;
            return this;
        }

        /**
         * Set desired number of uses.
         *
         * @param numUses the number of uses
         * @return self
         */
        public Builder withNumUses(final Integer numUses) {
            this.numUses = numUses;
            return this;
        }

        /**
         * Set TRUE if the token should be created without parent.
         *
         * @param noParent if TRUE, token is created as orphan
         * @return self
         */
        public Builder withNoParent(final boolean noParent) {
            this.noParent = noParent;
            return this;
        }

        /**
         * Create token without parent.
         * Convenience method for withNoParent()
         *
         * @return self
         */
        public Builder asOrphan() {
            return withNoParent(true);
        }

        /**
         * Create token with parent.
         * Convenience method for withNoParent()
         *
         * @return self
         */
        public Builder withParent() {
            return withNoParent(false);
        }

        /**
         * Set TRUE if the default policy should not be part of this token.
         *
         * @param noDefaultPolicy if TRUE, default policy is not attached
         * @return self
         */
        public Builder withNoDefaultPolicy(final boolean noDefaultPolicy) {
            this.noDefaultPolicy = noDefaultPolicy;
            return this;
        }

        /**
         * Attach default policy to token.
         * Convenience method for withNoDefaultPolicy()
         *
         * @return self
         */
        public Builder withDefaultPolicy() {
            return withNoDefaultPolicy(false);
        }

        /**
         * Do not attach default policy to token.
         * Convenience method for withNoDefaultPolicy()
         *
         * @return self
         */
        public Builder withoutDefaultPolicy() {
            return withNoDefaultPolicy(true);
        }

        /**
         * Add given policies.
         *
         * @param policies the policies
         * @return self
         * @since 0.5.0
         */
        public Builder withPolicies(final String... policies) {
            return withPolicies(Arrays.asList(policies));
        }

        /**
         * Add given policies.
         *
         * @param policies the policies
         * @return self
         */
        public Builder withPolicies(final List<String> policies) {
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
        public Builder withPolicy(final String policy) {
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
        public Builder withMeta(final Map<String, String> meta) {
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
        public Builder withMeta(final String key, final String value) {
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
        public Builder withRenewable(final Boolean renewable) {
            this.renewable = renewable;
            return this;
        }

        /**
         * Set token to be renewable.
         * Convenience method for withRenewable()
         *
         * @return self
         */
        public Builder renewable() {
            return withRenewable(true);
        }

        /**
         * Set token to be not renewable.
         * Convenience method for withRenewable()
         *
         * @return self
         */
        public Builder notRenewable() {
            return withRenewable(false);
        }

        /**
         * Set token period (former lease time).
         *
         * @param period Period in seconds.
         * @return self
         */
        public Builder withPeriod(final Integer period) {
            this.period = period;
            return this;
        }

        /**
         * Set entity alias for token.
         * Only works in combination with an associated token role.
         *
         * @param entityAlias Entity alias.
         * @return self
         */
        public Builder withEntityAlias(final String entityAlias) {
            this.entityAlias = entityAlias;
            return this;
        }

        /**
         * Build the token based on given parameters.
         *
         * @return the token
         */
        public Token build() {
            return new Token(this);
        }
    }
}
