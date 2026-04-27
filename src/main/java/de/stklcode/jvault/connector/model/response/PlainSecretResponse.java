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

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Vault response for plain secret responses.
 *
 * @param responseHeader Response metadata
 * @param data           Secret data
 * @author Stefan Kalscheuer
 * @since 1.1 abstract
 * @since 2.0 class is now a record
 */
public record PlainSecretResponse(
    @JsonUnwrapped Header responseHeader,
    Map<String, Serializable> data
) implements SecretResponse {

    @Override
    public Map<String, Serializable> data() {
        return Objects.requireNonNullElseGet(data, Collections::emptyMap);
    }

    @Override
    public VersionMetadata metadata() {
        return null;
    }
}
