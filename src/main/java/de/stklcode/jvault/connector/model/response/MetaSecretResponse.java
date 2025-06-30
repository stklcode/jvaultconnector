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

package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.model.response.embedded.SecretWrapper;
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Vault response for secret responses with metadata.
 *
 * @author Stefan Kalscheuer
 * @since 1.1 abstract
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MetaSecretResponse extends SecretResponse {
    @Serial
    private static final long serialVersionUID = -1076542846391240162L;

    @JsonProperty("data")
    private SecretWrapper secret;

    @Override
    public final Map<String, Serializable> getData() {
        if (secret != null) {
            return secret.getData();
        } else {
            return Collections.emptyMap();
        }
    }

    @Override
    public final VersionMetadata getMetadata() {
        if (secret != null) {
            return secret.getMetadata();
        } else {
            return null;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        MetaSecretResponse that = (MetaSecretResponse) o;
        return Objects.equals(secret, that.secret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), secret);
    }
}
