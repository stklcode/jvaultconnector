/*
 * Copyright 2016-2025 Stefan Kalscheuer
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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.Objects;

/**
 * Wrapping information object.
 *
 * @author Stefan Kalscheuer
 * @since 1.1
 */
public class WrapInfo implements Serializable {
    private static final long serialVersionUID = 4864973237090355607L;

    @JsonProperty("token")
    private String token;

    @JsonProperty("ttl")
    private Integer ttl;

    @JsonProperty("creation_time")
    private ZonedDateTime creationTime;

    @JsonProperty("creation_path")
    private String creationPath;

    /**
     * @return Token
     */
    public String getToken() {
        return token;
    }

    /**
     * @return TTL (in seconds)
     */
    public Integer getTtl() {
        return ttl;
    }

    /**
     * @return Creation time
     */
    public ZonedDateTime getCreationTime() {
        return creationTime;
    }

    /**
     * @return Creation path
     */
    public String getCreationPath() {
        return creationPath;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        WrapInfo that = (WrapInfo) o;
        return Objects.equals(token, that.token) &&
            Objects.equals(ttl, that.ttl) &&
            Objects.equals(creationTime, that.creationTime) &&
            Objects.equals(creationPath, that.creationPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token, ttl, creationTime, creationPath);
    }
}
