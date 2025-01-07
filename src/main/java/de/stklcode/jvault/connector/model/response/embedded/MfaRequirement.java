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
import java.util.Map;
import java.util.Objects;

/**
 * Embedded multi-factor-authentication (MFA) requirement.
 *
 * @author Stefan Kalscheuer
 * @since 1.2
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class MfaRequirement implements Serializable {
    private static final long serialVersionUID = -2516941512455319638L;

    @JsonProperty("mfa_request_id")
    private String mfaRequestId;

    @JsonProperty("mfa_constraints")
    private Map<String, MfaConstraintAny> mfaConstraints;

    /**
     * @return MFA request ID
     */
    public String getMfaRequestId() {
        return mfaRequestId;
    }

    /**
     * @return MFA constraints
     */
    public Map<String, MfaConstraintAny> getMfaConstraints() {
        return mfaConstraints;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MfaRequirement mfaRequirement = (MfaRequirement) o;
        return Objects.equals(mfaRequestId, mfaRequirement.mfaRequestId) &&
            Objects.equals(mfaConstraints, mfaRequirement.mfaConstraints);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mfaRequestId, mfaConstraints);
    }
}
