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
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;

/**
 * Embedded metadata for Key-Value v2 secrets.
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 * @since 1.1 implements {@link Serializable}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class SecretMetadata implements Serializable {
    private static final long serialVersionUID = -4967896264361344676L;

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSXXX");

    @JsonProperty("created_time")
    private ZonedDateTime createdTime;

    @JsonProperty("current_version")
    private Integer currentVersion;

    @JsonProperty("max_versions")
    private Integer maxVersions;

    @JsonProperty("oldest_version")
    private Integer oldestVersion;

    @JsonProperty("updated_time")
    private ZonedDateTime updatedTime;

    @JsonProperty("versions")
    private Map<Integer, VersionMetadata> versions;

    /**
     * @return Time of secret creation as raw string representation.
     * @deprecated Method left for backwards compatibility only. Use {@link #getCreatedTime()} instead.
     */
    @Deprecated(since = "1.2", forRemoval = true)
    public String getCreatedTimeString() {
        if (createdTime != null) {
            return TIME_FORMAT.format(createdTime);
        }

        return null;
    }

    /**
     * @return Time of secret creation.
     */
    public ZonedDateTime getCreatedTime() {
        return createdTime;
    }

    /**
     * @return Current version number.
     */
    public Integer getCurrentVersion() {
        return currentVersion;
    }

    /**
     * @return Maximum number of versions.
     */
    public Integer getMaxVersions() {
        return maxVersions;
    }

    /**
     * @return Oldest available version number.
     */
    public Integer getOldestVersion() {
        return oldestVersion;
    }

    /**
     * @return Time of secret update as raw string representation.
     * @deprecated Method left for backwards compatibility only. Use {@link #getUpdatedTime()} instead.
     */
    @Deprecated(since = "1.2", forRemoval = true)
    public String getUpdatedTimeString() {
        if (updatedTime != null) {
            return TIME_FORMAT.format(updatedTime);
        }

        return null;
    }

    /**
     * @return Time of secret update.
     */
    public ZonedDateTime getUpdatedTime() {
        return updatedTime;
    }

    /**
     * @return Version of the entry.
     */
    public Map<Integer, VersionMetadata> getVersions() {
        return versions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SecretMetadata that = (SecretMetadata) o;
        return Objects.equals(createdTime, that.createdTime) &&
                Objects.equals(currentVersion, that.currentVersion) &&
                Objects.equals(maxVersions, that.maxVersions) &&
                Objects.equals(oldestVersion, that.oldestVersion) &&
                Objects.equals(updatedTime, that.updatedTime) &&
                Objects.equals(versions, that.versions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(createdTime, currentVersion, maxVersions, oldestVersion, updatedTime, versions);
    }
}
