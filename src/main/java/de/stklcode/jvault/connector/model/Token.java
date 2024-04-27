/*
 * Copyright 2016-2024 Stefan Kalscheuer
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

import java.io.Serializable;
import java.util.*;

/**
 * Vault Token metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @since 1.1 implements {@link Serializable}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class Token implements Serializable {
    private static final long serialVersionUID = 5208508683665365287L;

    @JsonProperty("id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    @JsonProperty("type")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String type;

    @JsonProperty("display_name")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String displayName;

    @JsonProperty("no_parent")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean noParent;

    @JsonProperty("no_default_policy")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean noDefaultPolicy;

    @JsonProperty("ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer ttl;

    @JsonProperty("explicit_max_ttl")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer explicitMaxTtl;

    @JsonProperty("num_uses")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer numUses;

    @JsonProperty("policies")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> policies;

    @JsonProperty("meta")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Map<String, String> meta;

    @JsonProperty("renewable")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean renewable;

    @JsonProperty("period")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Integer period;

    @JsonProperty("entity_alias")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String entityAlias;

    /**
     * Construct empty {@link Token} object.
     */
    public Token() {
    }

    /**
     * Construct {@link Token} object from {@link Builder}.
     *
     * @param builder Token builder.
     */
    public Token(final Builder builder) {
        this.id = builder.id;
        this.type = builder.type != null ? builder.type.value() : null;
        this.displayName = builder.displayName;
        this.noParent = builder.noParent;
        this.noDefaultPolicy = builder.noDefaultPolicy;
        this.ttl = builder.ttl;
        this.explicitMaxTtl = builder.explicitMaxTtl;
        this.numUses = builder.numUses;
        this.policies = builder.policies;
        this.meta = builder.meta;
        this.renewable = builder.renewable;
        this.period = builder.period;
        this.entityAlias = builder.entityAlias;
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
     * @return Token ID
     */
    public String getId() {
        return id;
    }

    /**
     * @return Token type
     * @since 0.9
     */
    public String getType() {
        return type;
    }

    /**
     * @return Token display name
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * @return Token has no parent
     */
    public Boolean getNoParent() {
        return noParent;
    }

    /**
     * @return Token has no default policy
     */
    public Boolean getNoDefaultPolicy() {
        return noDefaultPolicy;
    }

    /**
     * @return Time-to-live in seconds
     */
    public Integer getTtl() {
        return ttl;
    }

    /**
     * @return Explicit maximum time-to-live in seconds
     * @since 0.9
     */
    public Integer getExplicitMaxTtl() {
        return explicitMaxTtl;
    }

    /**
     * @return Number of uses
     */
    public Integer getNumUses() {
        return numUses;
    }

    /**
     * @return List of policies
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * @return Metadata
     */
    public Map<String, String> getMeta() {
        return meta;
    }

    /**
     * @return Token is renewable
     */
    public Boolean isRenewable() {
        return renewable;
    }

    /**
     * @return Token period.
     * @since 0.9
     */
    public Integer getPeriod() {
        return period;
    }

    /**
     * @return Token entity alias.
     * @since 0.9
     */
    public String getEntityAlias() {
        return entityAlias;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Token token = (Token) o;
        return Objects.equals(id, token.id) &&
                Objects.equals(type, token.type) &&
                Objects.equals(displayName, token.displayName) &&
                Objects.equals(noParent, token.noParent) &&
                Objects.equals(noDefaultPolicy, token.noDefaultPolicy) &&
                Objects.equals(ttl, token.ttl) &&
                Objects.equals(explicitMaxTtl, token.explicitMaxTtl) &&
                Objects.equals(numUses, token.numUses) &&
                Objects.equals(policies, token.policies) &&
                Objects.equals(meta, token.meta) &&
                Objects.equals(renewable, token.renewable) &&
                Objects.equals(period, token.period) &&
                Objects.equals(entityAlias, token.entityAlias);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, displayName, noParent, noDefaultPolicy, ttl, explicitMaxTtl, numUses, policies,
                meta, renewable, period, entityAlias);
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
        private Integer ttl;
        private Integer explicitMaxTtl;
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
        public Builder withTtl(final Integer ttl) {
            this.ttl = ttl;
            return this;
        }

        /**
         * Set desired explicit maximum time to live.
         *
         * @param explicitMaxTtl the explicit max. TTL
         * @return self
         */
        public Builder withExplicitMaxTtl(final Integer explicitMaxTtl) {
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
