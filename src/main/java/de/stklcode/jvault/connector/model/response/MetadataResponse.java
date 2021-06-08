/*
 * Copyright 2016-2021 Stefan Kalscheuer
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
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.SecretMetadata;

import java.io.IOException;
import java.util.Map;

/**
 * Vault response for secret metadata (KV v2).
 *
 * @author Stefan Kalscheuer
 * @since 0.8
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MetadataResponse extends VaultDataResponse {

    private SecretMetadata metadata;

    @Override
    public final void setData(final Map<String, Object> data) throws InvalidResponseException {
        var mapper = new ObjectMapper();
        try {
            this.metadata = mapper.readValue(mapper.writeValueAsString(data), SecretMetadata.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Failed deserializing response", e);
        }
    }

    /**
     * Get the actual metadata.
     *
     * @return Metadata.
     */
    public SecretMetadata getMetadata() {
        return metadata;
    }
}
