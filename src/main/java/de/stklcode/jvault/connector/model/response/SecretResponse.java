/*
 * Copyright 2016-2017 Stefan Kalscheuer
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

import java.io.IOException;
import java.util.Map;

/**
 * Vault response for secret request.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretResponse extends VaultDataResponse {
    private Map<String, Object> data;

    @Override
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        this.data = data;
    }

    /**
     * Get complete data object.
     *
     * @return data map
     * @since 0.4.0
     */
    public Map<String, Object> getData() {
        return data;
    }

    /**
     * Get a single value for given key.
     *
     * @param key the key
     * @return the value or NULL if absent
     * @since 0.4.0
     */
    public Object get(String key) {
        return data.get(key);
    }

    /**
     * Get data element for key "value".
     * Method for backwards compatibility in case of simple secrets.
     *
     * @return the value
     */
    public String getValue() {
        if (data.get("value") == null)
            return null;
        return data.get("value").toString();
    }

    /**
     * Get response parsed as JSON
     *
     * @param type Class to parse response
     * @param <T>  Class to parse response
     * @return Parsed object
     * @throws InvalidResponseException on parsing error
     * @since 0.3
     */
    public <T> T getValue(Class<T> type) throws InvalidResponseException {
        return get("value", type);
    }

    /**
     * Get response parsed as JSON
     *
     * @param key the key
     * @param type Class to parse response
     * @param <T>  Class to parse response
     * @return Parsed object
     * @throws InvalidResponseException on parsing error
     * @since 0.4.0
     */
    public <T> T get(String key, Class<T> type) throws InvalidResponseException {
        try {
            return new ObjectMapper().readValue(get(key).toString(), type);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response payload: " + e.getMessage());
        }
    }
}