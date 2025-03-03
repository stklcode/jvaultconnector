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

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Embedded multi-factor-authentication (MFA) constraint "any".
 *
 * @author Stefan Kalscheuer
 * @since 1.2
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class MfaConstraintAny implements Serializable {
    private static final long serialVersionUID = 1226126781813149627L;

    @JsonProperty("any")
    private List<MfaMethodId> any;

    /**
     * @return List of "any" MFA methods
     */
    public List<MfaMethodId> getAny() {
        return any;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MfaConstraintAny mfaRequirement = (MfaConstraintAny) o;
        return Objects.equals(any, mfaRequirement.any);
    }

    @Override
    public int hashCode() {
        return Objects.hash(any);
    }
}
