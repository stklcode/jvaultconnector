/*
 * Copyright 2016-2022 Stefan Kalscheuer
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
import java.time.format.DateTimeParseException;
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
    private static final long serialVersionUID = -5286693953873839611L;

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSX");

    @JsonProperty("created_time")
    private String createdTimeString;

    @JsonProperty("deletion_time")
    private String deletionTimeString;

    @JsonProperty("destroyed")
    private boolean destroyed;

    @JsonProperty("version")
    private Integer version;

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
     * @return Time for secret deletion as raw string representation.
     */
    public String getDeletionTimeString() {
        return deletionTimeString;
    }

    /**
     * @return Time for secret deletion.
     */
    public ZonedDateTime getDeletionTime() {
        if (deletionTimeString != null && !deletionTimeString.isEmpty()) {
            try {
                return ZonedDateTime.parse(deletionTimeString, TIME_FORMAT);
            } catch (DateTimeParseException e) {
                // Ignore.
            }
        }

        return null;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        VersionMetadata that = (VersionMetadata) o;
        return destroyed == that.destroyed &&
                Objects.equals(createdTimeString, that.createdTimeString) &&
                Objects.equals(deletionTimeString, that.deletionTimeString) &&
                Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(createdTimeString, deletionTimeString, destroyed, version);
    }
}
