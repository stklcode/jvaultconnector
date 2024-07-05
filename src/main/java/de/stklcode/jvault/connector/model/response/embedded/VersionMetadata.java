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

package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Embedded metadata for a single Key-Value v2 version.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 * @since 1.1 implements {@link Serializable}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class VersionMetadata implements Serializable {
    private static final long serialVersionUID = 8495687554714216478L;

    @JsonProperty("created_time")
    private ZonedDateTime createdTime;

    @JsonProperty("deletion_time")
    private ZonedDateTime deletionTime;

    @JsonProperty("destroyed")
    private boolean destroyed;

    @JsonProperty("version")
    private Integer version;

    @JsonProperty("custom_metadata")
    private HashMap<String, String> customMetadata;

    /**
     * @return Time of secret creation.
     */
    public ZonedDateTime getCreatedTime() {
        return createdTime;
    }

    /**
     * @return Time for secret deletion.
     */
    public ZonedDateTime getDeletionTime() {
        return deletionTime;
    }

    /**
     * @return Whether the secret is destroyed.
     */
    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * @return Version of the entry.
     */
    public Integer getVersion() {
        return version;
    }

    /**
     * @return Custom metadata.
     * @since 1.3
     */
    public Map<String, String> getCustomMetadata() {
        return customMetadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        VersionMetadata that = (VersionMetadata) o;
        return destroyed == that.destroyed &&
                Objects.equals(createdTime, that.createdTime) &&
                Objects.equals(deletionTime, that.deletionTime) &&
                Objects.equals(version, that.version) &&
                Objects.equals(customMetadata, that.customMetadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(createdTime, deletionTime, destroyed, version, customMetadata);
    }
}
