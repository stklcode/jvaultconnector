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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.response.embedded.TokenData;

import java.io.IOException;
import java.util.Map;

/**
 * Vault response from credentials lookup. Simple wrapper for data objects containing username and password fields.
 *
 * @author  Stefan Kalscheuer
 * @since   0.5.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class CredentialsResponse extends SecretResponse {

    public String getUsername() {
        if (get("username") != null)
            return get("username").toString();
        return null;
    }

    public String getPassword() {
        if (get("username") != null)
            return get("username").toString();
        return null;
    }
}
