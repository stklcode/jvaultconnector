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
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Authentication method response.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuthMethodsResponse extends VaultDataResponse {
    private static final long serialVersionUID = -1802724129533405375L;

    @JsonProperty("data")
    private Map<String, AuthMethod> supportedMethods;

    /**
     * Construct empty {@link AuthMethodsResponse} object.
     */
    public AuthMethodsResponse() {
        this.supportedMethods = new HashMap<>();
    }

    /**
     * @return Supported authentication methods
     */
    public Map<String, AuthMethod> getSupportedMethods() {
        return supportedMethods;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        AuthMethodsResponse that = (AuthMethodsResponse) o;
        return Objects.equals(supportedMethods, that.supportedMethods);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), supportedMethods);
    }
}
