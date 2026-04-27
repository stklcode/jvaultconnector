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
import java.util.List;
import java.util.Map;

/**
 * Vault AppRole role metamodel.
 *
 * @param id              Secret ID
 * @param accessor        Secret accessor
 * @param metadata        Secret metadata
 * @param cidrList        List of bound subnets in CIDR notation
 * @param tokenBoundCidrs List of bound CIDR subnets of associated tokens
 * @param creationTime    Creation time
 * @param expirationTime  Expiration time
 * @param lastUpdatedTime Time of last update
 * @param numUses         Number of uses
 * @param ttl             Time-to-live
 * @author Stefan Kalscheuer
 * @since 0.4.0
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
public record AppRoleSecret(
    @JsonProperty("secret_id") @JsonInclude(JsonInclude.Include.NON_NULL) String id,
    @JsonProperty(value = "secret_id_accessor", access = JsonProperty.Access.WRITE_ONLY) String accessor,
    @JsonInclude(JsonInclude.Include.NON_EMPTY) Map<String, Object> metadata,
    @JsonDeserialize(using = CommaSeparatedArrayDeserializer.class) List<String> cidrList,
    @JsonDeserialize(using = CommaSeparatedArrayDeserializer.class) List<String> tokenBoundCidrs,
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String creationTime,
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String expirationTime,
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String lastUpdatedTime,
    @JsonProperty(value = "secret_id_num_uses", access = JsonProperty.Access.WRITE_ONLY) Integer numUses,
    @JsonProperty(value = "secret_id_ttl", access = JsonProperty.Access.WRITE_ONLY) Integer ttl
) implements Serializable {

    /**
     * Construct empty {@link AppRoleSecret} object.
     */
    public AppRoleSecret() {
        this(null, null, null, null, null, null, null, null, null, null);
    }

    /**
     * Construct {@link AppRoleSecret} with secret ID.
     *
     * @param id Secret ID
     */
    public AppRoleSecret(final String id) {
        this(id, null, null, null, null, null, null, null, null, null);
    }

    /**
     * Construct {@link AppRoleSecret} with ID and metadata.
     *
     * @param id       Secret ID
     * @param metadata Secret metadata
     * @param cidrList List of subnets in CIDR notation, the role is bound to
     */
    public AppRoleSecret(final String id, final Map<String, Object> metadata, final List<String> cidrList) {
        this(id, null, metadata, cidrList, null, null, null, null, null, null);
    }

    /**
     * @return List of bound subnets in CIDR notation as comma-separated {@link String}
     */
    @JsonGetter("cidr_list")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String cidrListString() {
        if (cidrList == null || cidrList.isEmpty()) {
            return "";
        }
        return String.join(",", cidrList);
    }

    /**
     * @return list of subnets in CIDR notation as comma-separated {@link String}
     * @since 1.5.3
     */
    @JsonGetter("token_bound_cidrs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String tokenBoundCidrsString() {
        if (tokenBoundCidrs == null || tokenBoundCidrs.isEmpty()) {
            return "";
        }
        return String.join(",", tokenBoundCidrs);
    }
}
