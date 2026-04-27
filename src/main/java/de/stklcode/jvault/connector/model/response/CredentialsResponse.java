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

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import de.stklcode.jvault.connector.model.response.embedded.VersionMetadata;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;

/**
 * Vault response from credentials lookup. Simple wrapper for data objects containing username and password fields.
 *
 * @param responseHeader Response metadata
 * @param data           Secret data
 * @author Stefan Kalscheuer
 * @since 0.5.0
 * @since 2.0 class is now a record
 */
public record CredentialsResponse(
    @JsonUnwrapped Header responseHeader,
    Map<String, Serializable> data
) implements SecretResponse {
    @Serial
    private static final long serialVersionUID = -1439692963299045425L;

    /**
     * @return Username
     */
    public String username() {
        Object username = get("username");
        if (username != null) {
            return username.toString();
        }
        return null;
    }

    /**
     * @return Password
     */
    public String password() {
        Object password = get("password");
        if (password != null) {
            return password.toString();
        }
        return null;
    }

    @Override
    public VersionMetadata metadata() {
        return null;
    }
}
