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

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import tools.jackson.databind.annotation.JsonDeserialize;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Vault AppRole role metamodel.
 *
 * @param name                 Role name
 * @param id                   Role ID
 * @param bindSecretId         Bind secret ID
 * @param secretIdBoundCidrs   List of bound CIDR subnets
 * @param secretIdNumUses      Maximum number of uses per secret
 * @param secretIdTtl          Maximum TTL in seconds for secrets
 * @param localSecretIds       Enable local secret IDs?
 * @param tokenTtl             Token TTL in seconds
 * @param tokenMaxTtl          Maximum token TTL in seconds, including renewals
 * @param tokenPolicies        List of token policies
 * @param tokenBoundCidrs      List of bound CIDR subnets of associated tokens
 * @param tokenExplicitMaxTtl  Explicit maximum token TTL in seconds, including renewals
 * @param tokenNoDefaultPolicy Enable default policy for token?
 * @param tokenNumUses         Number of uses for token
 * @param tokenPeriod          Duration in seconds, if specified
 * @param tokenType            Token type
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AppRole(
    @JsonProperty("role_name") String name,
    @JsonProperty("role_id") String id,
    Boolean bindSecretId,
    @JsonDeserialize(using = CommaSeparatedArrayDeserializer.class) List<String> secretIdBoundCidrs,
    Integer secretIdNumUses,
    Long secretIdTtl,
    Boolean localSecretIds,
    Long tokenTtl,
    Long tokenMaxTtl,
    @JsonDeserialize(using = CommaSeparatedArrayDeserializer.class) List<String> tokenPolicies,
    @JsonDeserialize(using = CommaSeparatedArrayDeserializer.class) List<String> tokenBoundCidrs,
    Long tokenExplicitMaxTtl,
    Boolean tokenNoDefaultPolicy,
    Integer tokenNumUses,
    Integer tokenPeriod,
    String tokenType
) implements Serializable {

    /**
     * Construct {@link AppRole} object from {@link AppRole.Builder}.
     *
     * @param builder AppRole builder.
     */
    private AppRole(final Builder builder) {
        this(
            builder.name,
            builder.id,
            builder.bindSecretId,
            builder.secretIdBoundCidrs,
            builder.secretIdNumUses,
            builder.secretIdTtl,
            builder.localSecretIds,
            builder.tokenTtl,
            builder.tokenMaxTtl,
            builder.tokenPolicies,
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
     * @param name Role name.
     * @return AppRole Builder.
     * @since 0.8
     */
    public static Builder builder(final String name) {
        return new Builder(name);
    }

    /**
     * @return list of subnets in CIDR notation as comma-separated {@link String}
     * @since 0.9
     */
    @JsonGetter("token_bound_cidrs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String tokenBoundCidrsString() {
        if (tokenBoundCidrs == null || tokenBoundCidrs.isEmpty()) {
            return "";
        }
        return String.join(",", tokenBoundCidrs);
    }

    /**
     * @return List of subnets in CIDR notation as comma-separated {@link String}
     * @since 0.8 replaces {@code getBoundCidrListString()} ()}
     */
    @JsonGetter("secret_id_bound_cidrs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String secretIdBoundCidrsString() {
        if (secretIdBoundCidrs == null || secretIdBoundCidrs.isEmpty()) {
            return "";
        }
        return String.join(",", secretIdBoundCidrs);
    }

    /**
     * @return list of policies as comma-separated {@link String}
     * @since 0.9
     */
    @JsonGetter("token_policies")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String tokenPoliciesString() {
        if (tokenPolicies == null || tokenPolicies.isEmpty()) {
            return "";
        }
        return String.join(",", tokenPolicies);
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
        private Long secretIdTtl;
        private Boolean localSecretIds;
        private Long tokenTtl;
        private Long tokenMaxTtl;
        private List<String> tokenBoundCidrs;
        private Long tokenExplicitMaxTtl;
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
        public Builder withSecretIdTtl(final Long secretIdTtl) {
            this.secretIdTtl = secretIdTtl;
            return this;
        }

        /**
         * Enable or disable local secret IDs.
         *
         * @param localSecretIds Enable local secret IDs?
         * @return self
         * @since 0.9
         * @since 1.3 renamed to {@code withLocalSecretIds()}
         */
        public Builder withLocalSecretIds(final Boolean localSecretIds) {
            this.localSecretIds = localSecretIds;
            return this;
        }

        /**
         * Set default token TTL in seconds.
         *
         * @param tokenTtl the TTL
         * @return self
         */
        public Builder withTokenTtl(final Long tokenTtl) {
            this.tokenTtl = tokenTtl;
            return this;
        }

        /**
         * Set maximum token TTL in seconds.
         *
         * @param tokenMaxTtl the TTL
         * @return self
         */
        public Builder withTokenMaxTtl(final Long tokenMaxTtl) {
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
        public Builder withTokenExplicitMaxTtl(final Long tokenExplicitMaxTtl) {
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
