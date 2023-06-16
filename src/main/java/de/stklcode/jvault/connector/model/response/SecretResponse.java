/*
 * Copyright 2016-2023 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;

import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

/**
 * Vault response for secret request.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 1.1 abstract
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class SecretResponse extends VaultDataResponse {
    private static final long serialVersionUID = 5198088815871692951L;

    /**
     * Get complete data object.
     *
     * @return data map
     * @since 0.4.0
     * @since 1.1 Serializable map value.
     */
    public abstract Map<String, Serializable> getData();

    /**
     * Get secret metadata. This is only available for KV v2 secrets.
     *
     * @return Metadata of the secret.
     * @since 0.8
     */
    public abstract VersionMetadata getMetadata();

    /**
     * Get a single value for given key.
     *
     * @param key the key
     * @return the value or {@code null} if absent
     * @since 0.4.0
     */
    public final Object get(final String key) {
        return getData().get(key);
    }

    /**
     * Get response parsed as JSON.
     *
     * @param key  the key
     * @param type Class to parse response
     * @param <C>  Class to parse response
     * @return Parsed object or {@code null} if absent
     * @throws InvalidResponseException on parsing error
     * @since 0.4.0
     */
    public final <C> C get(final String key, final Class<C> type) throws InvalidResponseException {
        try {
            Object rawValue = get(key);
            if (rawValue == null) {
                return null;
            } else if (type.isInstance(rawValue)) {
                return type.cast(rawValue);
            } else {
                var om = new ObjectMapper();
                return om.readValue(om.writeValueAsString(rawValue), type);
            }
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response payload: " + e.getMessage());
        }
    }
}
