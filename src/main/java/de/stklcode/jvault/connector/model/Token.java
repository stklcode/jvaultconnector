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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Vault Token metamodel.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class Token {
    @JsonProperty("id")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

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

    public Token(final String id, final String displayName, final Boolean noParent, final Boolean noDefaultPolicy,
                 final Integer ttl, final Integer numUses, final List<String> policies, final Map<String, String> meta,
                 final Boolean renewable) {
        this.id = id;
        this.displayName = displayName;
        this.ttl = ttl;
        this.numUses = numUses;
        this.noParent = noParent;
        this.noDefaultPolicy = noDefaultPolicy;
        this.policies = policies;
        this.meta = meta;
        this.renewable = renewable;
    }

    public String getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Boolean getNoParent() {
        return noParent;
    }

    public Boolean getNoDefaultPolicy() {
        return noDefaultPolicy;
    }

    public Integer getTtl() {
        return ttl;
    }

    public Integer getNumUses() {
        return numUses;
    }

    public List<String> getPolicies() {
        return policies;
    }

    public Map<String, String> getMeta() {
        return meta;
    }

    public Boolean isRenewable() {
        return renewable;
    }
}
