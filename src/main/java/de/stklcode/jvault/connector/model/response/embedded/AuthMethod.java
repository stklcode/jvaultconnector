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

import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.model.AuthBackend;

import java.io.Serializable;
import java.util.Map;

/**
 * Embedded authentication method response.
 *
 * @param rawType               Backend type
 * @param accessor              Accessor
 * @param deprecationStatus     Deprecation status
 * @param description           Description
 * @param config                Configuration data
 * @param externalEntropyAccess Backend has access to external entropy source
 * @param local                 Is local backend
 * @param options               Options
 * @param pluginVersion         Plugin version
 * @param runningPluginVersion  Running plugin version
 * @param runningSha256         Running SHA256
 * @param sealWrap              Seal wrapping enabled
 * @param uuid                  Backend UUID
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
public record AuthMethod(
    @JsonProperty("type") String rawType,
    String accessor,
    String deprecationStatus,
    String description,
    MountConfig config,
    boolean externalEntropyAccess,
    boolean local,
    Map<String, String> options,
    String pluginVersion,
    String runningPluginVersion,
    String runningSha256,
    boolean sealWrap,
    String uuid
) implements Serializable {

    /**
     * Get parsed backend type.
     *
     * @return Backend type
     */
    public AuthBackend type() {
        return AuthBackend.forType(rawType);
    }

}
