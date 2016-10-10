/*
 * Copyright 2016 Stefan Kalscheuer
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
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretResponse extends VaultDataResponse {
    private String value;

    @Override
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        try {
            this.value = (String) data.get("value");
        } catch (ClassCastException e) {
            throw new InvalidResponseException("Value could not be parsed", e);
        }
    }

    public String getValue() {
        return value;
    }

    /**
     * Get response parsed as JSON
     * @param type  Class to parse response
     * @param <T>   Class to parse response
     * @return      Parsed object
     * @throws InvalidResponseException on parsing error
     * @since 0.3
     */
    public <T> T getValue(Class<T> type) throws InvalidResponseException {
        try {
            return new ObjectMapper().readValue(getValue(), type);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response payload: " + e.getMessage());
        }
    }
}