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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;

import java.io.Serial;
import java.util.Objects;

/**
 * Vault response for a single secret version metadata, i.e. after update (KV v2).
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretVersionResponse extends VaultDataResponse {
    @Serial
    private static final long serialVersionUID = 2748635005258576174L;

    @JsonProperty("data")
    private VersionMetadata metadata;

    /**
     * Get the actual metadata.
     *
     * @return Metadata.
     */
    public VersionMetadata getMetadata() {
        return metadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        SecretVersionResponse that = (SecretVersionResponse) o;
        return Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), metadata);
    }
}
