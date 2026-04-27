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

package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.stklcode.jvault.connector.model.response.embedded.SecretWrapper;
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;

/**
 * Vault response for secret responses with metadata.
 *
 * @param responseHeader Response metadata
 * @param secretWrapper  Secret data wrapper
 * @author Stefan Kalscheuer
 * @since 1.1
 * @since 2.0 class is now a record
 */
public record MetaSecretResponse(
    @JsonUnwrapped Header responseHeader,
    @JsonProperty("data") SecretWrapper secretWrapper
) implements SecretResponse {

    @Override
    public Map<String, Serializable> data() {
        if (secretWrapper != null) {
            return secretWrapper.data();
        } else {
            return Collections.emptyMap();
        }
    }

    @Override
    public VersionMetadata metadata() {
        if (secretWrapper != null) {
            return secretWrapper.metadata();
        } else {
            return null;
        }
    }
}
