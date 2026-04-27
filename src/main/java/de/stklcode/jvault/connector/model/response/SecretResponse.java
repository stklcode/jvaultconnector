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

import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.io.Serializable;
import java.util.Map;

/**
 * Vault response for secret request.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 1.1 abstract
 * @since 2.0 abstract class is now an interface
 */
public interface SecretResponse extends VaultDataResponse {

    /**
     * Get complete data object.
     *
     * @return data map
     * @since 0.4.0
     * @since 1.1 Serializable map value.
     */
    Map<String, Serializable> data();

    /**
     * Get secret metadata. This is only available for KV v2 secrets.
     *
     * @return Metadata of the secret.
     * @since 0.8
     */
    VersionMetadata metadata();

    /**
     * Get a single value for given key.
     *
     * @param key the key
     * @return the value or {@code null} if absent
     * @since 0.4.0
     */
    default Object get(final String key) {
        if (data() != null) {
            return data().get(key);
        }
        return null;
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
    default <C> C get(final String key, final Class<C> type) throws InvalidResponseException {
        try {
            Object rawValue = get(key);
            if (rawValue == null) {
                return null;
            } else if (type.isInstance(rawValue)) {
                return type.cast(rawValue);
            } else {
                var om = JsonMapper.builder()
                    .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                    .disable(DateTimeFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE)
                    .disable(DateTimeFeature.WRITE_DATES_WITH_CONTEXT_TIME_ZONE)
                    .build();

                if (rawValue instanceof String stringValue) {
                    return om.readValue(stringValue, type);
                } else {
                    return om.readValue(om.writeValueAsString(rawValue), type);
                }
            }
        } catch (JacksonException e) {
            throw new InvalidResponseException("Unable to parse response payload: " + e.getMessage());
        }
    }
}
