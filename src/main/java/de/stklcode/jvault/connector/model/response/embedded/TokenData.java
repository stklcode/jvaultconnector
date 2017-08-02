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

package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Embedded token information inside Vault response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class TokenData {
    @JsonProperty("accessor")
    private String accessor;

    @JsonProperty("creation_time")
    private Integer creationTime;

    @JsonProperty("creation_ttl")
    private Integer creatinTtl;

    @JsonProperty("display_name")
    private String name;

    @JsonProperty("id")
    private String id;

    @JsonProperty("meta")
    private String meta;

    @JsonProperty("num_uses")
    private Integer numUses;

    @JsonProperty("orphan")
    private boolean orphan;

    @JsonProperty("path")
    private String path;

    @JsonProperty("role")
    private String role;

    @JsonProperty("ttl")
    private Integer ttl;

    public String getAccessor() {
        return accessor;
    }

    public Integer getCreationTime() {
        return creationTime;
    }

    public Integer getCreatinTtl() {
        return creatinTtl;
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public Integer getNumUses() {
        return numUses;
    }

    public boolean isOrphan() {
        return orphan;
    }

    public String getPath() {
        return path;
    }

    public String getRole() {
        return role;
    }

    public Integer getTtl() {
        return ttl;
    }

    public String getMeta() {
        return meta;
    }
}