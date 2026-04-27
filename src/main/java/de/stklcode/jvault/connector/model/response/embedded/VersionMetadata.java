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

package de.stklcode.jvault.connector.model.response.embedded;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.HashMap;

/**
 * Embedded metadata for a single Key-Value v2 version.
 *
 * @param createdTime    Time of secret creation
 * @param deletionTime   Time for secret deletion
 * @param destroyed      Whether the secret is destroyed
 * @param version        Version of the entry
 * @param customMetadata Custom metadata
 * @author Stefan Kalscheuer
 * @since 0.8
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
public record VersionMetadata(
    ZonedDateTime createdTime,
    ZonedDateTime deletionTime,
    boolean destroyed,
    Integer version,
    HashMap<String, String> customMetadata
) implements Serializable {
}
