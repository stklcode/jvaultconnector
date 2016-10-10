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
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication method response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthMethodsResponse extends VaultDataResponse {
    private Map<String, AuthMethod> supportedMethods;

    public AuthMethodsResponse() {
        this.supportedMethods = new HashMap<>();
    }

    @Override
    public void setData(Map<String, Object> data) throws InvalidResponseException {
        ObjectMapper mapper = new ObjectMapper();
        for (String path : data.keySet()) {
            try {
                this.supportedMethods.put(path, mapper.readValue(mapper.writeValueAsString(data.get(path)), AuthMethod.class));
            } catch (IOException e) {
                throw new InvalidResponseException();
            }
        }
    }

    public Map<String, AuthMethod> getSupportedMethods() {
        return supportedMethods;
    }
}
