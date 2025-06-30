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

package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Embedded multi-factor-authentication (MFA) requirement.
 *
 * @author Stefan Kalscheuer
 * @since 1.2
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class MfaMethodId implements Serializable {
    @Serial
    private static final long serialVersionUID = 691298070242998814L;

    @JsonProperty("type")
    private String type;

    @JsonProperty("id")
    private String id;

    @JsonProperty("uses_passcode")
    private Boolean usesPasscode;

    @JsonProperty("name")
    private String name;

    /**
     * @return MFA method type
     */
    public String getType() {
        return type;
    }

    /**
     * @return MFA method id
     */
    public String getId() {
        return id;
    }

    /**
     * @return MFA uses passcode id
     */
    public Boolean getUsesPasscode() {
        return usesPasscode;
    }

    /**
     * @return MFA method name
     */
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MfaMethodId mfaMethodId = (MfaMethodId) o;
        return Objects.equals(type, mfaMethodId.type) &&
            Objects.equals(id, mfaMethodId.id) &&
            Objects.equals(usesPasscode, mfaMethodId.usesPasscode) &&
            Objects.equals(name, mfaMethodId.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, id, usesPasscode, name);
    }
}
