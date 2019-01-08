/*
 * Copyright 2016-2019 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.exception.InvalidResponseException;

import java.util.List;
import java.util.Map;

/**
 * Vault response for secret list request.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class SecretListResponse extends VaultDataResponse {
    private List<String> keys;

    /**
     * Set data. Extracts list of keys from raw response data.
     *
     * @param data Raw data
     * @throws InvalidResponseException on parsing errors
     */
    @JsonProperty("data")
    public void setData(final Map<String, Object> data) throws InvalidResponseException {
        try {
            this.keys = (List<String>) data.get("keys");
        } catch (ClassCastException e) {
            throw new InvalidResponseException("Keys could not be parsed from data.", e);
        }
    }

    /**
     * @return List of secret keys
     */
    public List<String> getKeys() {
        return keys;
    }
}
