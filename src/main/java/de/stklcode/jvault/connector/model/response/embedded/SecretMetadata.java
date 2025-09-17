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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serial;
import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.HashMap;
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
    @Serial
    private static final long serialVersionUID = -905059942871916214L;

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

    @JsonProperty("cas_required")
    private Boolean casRequired;

    @JsonProperty("custom_metadata")
    private HashMap<String, String> customMetadata;

    @JsonProperty("delete_version_after")
    private String deleteVersionAfter;

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

    /**
     * @return CAS required?
     * @since 1.3
     */
    public Boolean isCasRequired() {
        return casRequired;
    }

    /**
     * @return Custom metadata.
     * @since 1.3
     */
    public Map<String, String> getCustomMetadata() {
        return customMetadata;
    }

    /**
     * @return time duration to delete version
     * @since 1.3
     */
    public String getDeleteVersionAfter() {
        return deleteVersionAfter;
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
            Objects.equals(versions, that.versions) &&
            Objects.equals(casRequired, that.casRequired) &&
            Objects.equals(customMetadata, that.customMetadata) &&
            Objects.equals(deleteVersionAfter, that.deleteVersionAfter);
    }

    @Override
    public int hashCode() {
        return Objects.hash(createdTime, currentVersion, maxVersions, oldestVersion, updatedTime, versions, casRequired,
            customMetadata, deleteVersionAfter);
    }
}
