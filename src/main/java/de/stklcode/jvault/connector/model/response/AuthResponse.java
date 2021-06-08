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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;

import java.io.IOException;
import java.util.Map;

/**
 * Vault response for authentication providing auth info in {@link AuthData} field.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuthResponse extends VaultDataResponse {
    private Map<String, Object> data;

    private AuthData auth;

    /**
     * Set authentication data. The input will be mapped to the {@link AuthData} model.
     *
     * @param auth Raw authentication data
     * @throws InvalidResponseException on mapping errors
     */
    @JsonProperty("auth")
    public void setAuth(final Map<String, Object> auth) throws InvalidResponseException {
        var mapper = new ObjectMapper();
        try {
            this.auth = mapper.readValue(mapper.writeValueAsString(auth), AuthData.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Failed deserializing response", e);
        }
    }

    @Override
    public void setData(final Map<String, Object> data) {
        this.data = data;
    }

    /**
     * @return Raw data
     */
    public Map<String, Object> getData() {
        return data;
    }

    /**
     * @return Authentication data
     */
    public AuthData getAuth() {
        return auth;
    }
}
