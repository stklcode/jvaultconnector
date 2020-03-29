/*
 * Copyright 2016-2019 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

/**
 * Embedded token information inside Vault response.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class TokenData {
    @JsonProperty("accessor")
    private String accessor;

    @JsonProperty("creation_time")
    private Integer creationTime;

    @JsonProperty("creation_ttl")
    private Integer creationTtl;

    @JsonProperty("display_name")
    private String name;

    @JsonProperty("entity_id")
    private String entityId;

    @JsonProperty("expire_time")
    private String expireTime;

    @JsonProperty("explicit_max_ttl")
    private Integer explicitMaxTtl;

    @JsonProperty("id")
    private String id;

    @JsonProperty("issue_time")
    private String issueTime;

    @JsonProperty("meta")
    private Map<String, Object> meta;

    @JsonProperty("num_uses")
    private Integer numUses;

    @JsonProperty("orphan")
    private boolean orphan;

    @JsonProperty("path")
    private String path;

    @JsonProperty("policies")
    private List<String> policies;

    @JsonProperty("renewable")
    private boolean renewable;

    @JsonProperty("ttl")
    private Integer ttl;

    @JsonProperty("type")
    private String type;

    /**
     * @return Token accessor
     */
    public String getAccessor() {
        return accessor;
    }

    /**
     * @return Creation time
     */
    public Integer getCreationTime() {
        return creationTime;
    }

    /**
     * @return Creation TTL (in seconds)
     */
    public Integer getCreationTtl() {
        return creationTtl;
    }

    /**
     * @return Token name
     */
    public String getName() {
        return name;
    }

    /**
     * @return Entity ID
     * @since 0.9
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * @return Expire time as raw string value
     * @since 0.9
     */
    public String getExpireTimeString() {
        return expireTime;
    }

    /**
     * @return Expire time (parsed)
     * @since 0.9
     */
    public ZonedDateTime getExpireTime() {
        if (expireTime == null) {
            return null;
        } else {
            return ZonedDateTime.parse(expireTime);
        }
    }

    /**
     * @return Explicit maximum TTL
     * @since 0.9
     */
    public Integer getExplicitMaxTtl() {
        return explicitMaxTtl;
    }

    /**
     * @return Token ID
     */
    public String getId() {
        return id;
    }

    /**
     * @return Issue time as raw string value
     * @since 0.9
     */
    public String getIssueTimeString() {
        return issueTime;
    }

    /**
     * @return Expire time (parsed)
     * @since 0.9
     */
    public ZonedDateTime getIssueTime() {
        if (issueTime == null) {
            return null;
        } else {
            return ZonedDateTime.parse(issueTime);
        }
    }

    /**
     * @return Token type
     * @since 0.9
     */
    public String getType() {
        return type;
    }

    /**
     * @return Number of uses
     */
    public Integer getNumUses() {
        return numUses;
    }

    /**
     * @return Token is orphan
     */
    public boolean isOrphan() {
        return orphan;
    }

    /**
     * @return Token path
     */
    public String getPath() {
        return path;
    }

    /**
     * @return Token policies
     * @since 0.9
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * @return Token is renewable
     * @since 0.9
     */
    public boolean isRenewable() {
        return renewable;
    }

    /**
     * @return Token TTL (in seconds)
     */
    public Integer getTtl() {
        return ttl;
    }

    /**
     * @return Metadata
     */
    public Map<String, Object> getMeta() {
        return meta;
    }
}
