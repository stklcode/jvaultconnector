/*
 * Copyright 2016-2020 Stefan Kalscheuer
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
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;

/**
 * Embedded metadata for Key-Value v2 secrets.
 *
 * @author  Stefan Kalscheuer
 * @since   0.8
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class SecretMetadata {
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSX");

    @JsonProperty("created_time")
    private String createdTimeString;

    @JsonProperty("current_version")
    private Integer currentVersion;

    @JsonProperty("max_versions")
    private Integer maxVersions;

    @JsonProperty("oldest_version")
    private Integer oldestVersion;

    @JsonProperty("updated_time")
    private String updatedTime;

    @JsonProperty("versions")
    private Map<Integer, VersionMetadata> versions;

    /**
     * @return Time of secret creation as raw string representation.
     */
    public String getCreatedTimeString() {
        return createdTimeString;
    }

    /**
     * @return Time of secret creation.
     */
    public ZonedDateTime getCreatedTime() {
        if (createdTimeString != null && !createdTimeString.isEmpty()) {
            try {
                return ZonedDateTime.parse(createdTimeString, TIME_FORMAT);
            } catch (DateTimeParseException e) {
                // Ignore.
            }
        }

        return null;
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
     */
    public String getUpdatedTimeString() {
        return updatedTime;
    }

    /**
     * @return Time of secret update..
     */
    public ZonedDateTime getUpdatedTime() {
        if (updatedTime != null && !updatedTime.isEmpty()) {
            try {
                return ZonedDateTime.parse(updatedTime, TIME_FORMAT);
            } catch (DateTimeParseException e) {
                // Ignore.
            }
        }

        return null;
    }

    /**
     * @return Version of the entry.
     */
    public Map<Integer, VersionMetadata> getVersions() {
        return versions;
    }

}
