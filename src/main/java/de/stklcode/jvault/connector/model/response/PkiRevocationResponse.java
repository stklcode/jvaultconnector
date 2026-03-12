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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;

import java.io.Serializable;

/**
 * Vault response for PKI certificate revocations.
 *
 * @param responseHeader Response metadata
 * @param data           PKI response data
 * @author Stefan Kalscheuer
 * @since 2.0.0
 */
public record PkiRevocationResponse(
    @JsonUnwrapped Header responseHeader,
    @JsonProperty("data") Data data
) implements VaultDataResponse {

    /**
     * Vault revocation response data.
     *
     * @param revocationTime        Revocation timestamp
     * @param revocationTimeRFC3339 Revocation time as RFC3339 string
     * @param state                 Revocation state (typically "revoked")
     */
    public record Data(
        @JsonProperty("revocation_time") Long revocationTime,
        @JsonProperty("revocation_time_rfc3339") String revocationTimeRFC3339,
        @JsonProperty("state") String state
    ) implements Serializable {
    }
}
