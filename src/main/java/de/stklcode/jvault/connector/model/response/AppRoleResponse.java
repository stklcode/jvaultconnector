/*
 * Copyright 2016-2022 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.model.AppRole;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Vault response for AppRole lookup.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppRoleResponse extends VaultDataResponse {
    private static final long serialVersionUID = -7817890935652200399L;

    private AppRole role;

    @Override
    public void setData(final Map<String, Object> data) throws InvalidResponseException {
        var mapper = new ObjectMapper();
        try {
            /* null empty strings on list objects */
            Map<String, Object> filteredData = new HashMap<>(data.size(), 1);
            data.forEach((k, v) -> {
                if (!(v instanceof String && ((String) v).isEmpty())) {
                    filteredData.put(k, v);
                }
            });
            this.role = mapper.readValue(mapper.writeValueAsString(filteredData), AppRole.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Failed deserializing response", e);
        }
    }

    /**
     * @return The role
     */
    public AppRole getRole() {
        return role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        AppRoleResponse that = (AppRoleResponse) o;
        return Objects.equals(role, that.role);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), role);
    }
}
