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
import java.util.List;

/**
 * Vault response for PKI CA/issuer certificate.
 *
 * @param responseHeader Response metadata
 * @param data           PKI response data
 * @author Stefan Kalscheuer
 * @since 2.0.0
 */
public record PkiCaResponse(
    @JsonUnwrapped Header responseHeader,
    @JsonProperty("data") Data data
) implements VaultDataResponse {

    /**
     * Vault CA certificate data.
     *
     * @param authorityKeyId        CA key ID (serial number)
     * @param certificate           CA certificate (PEM encoded)
     * @param revocationTime        CA certificate revocation timestamp (0 if not revoked)
     * @param revocationTimeRFC3339 CA certificate revocation time as RFC3339 string (empty if not revoked)
     * @param caChain               CA certificate chain (PEM encoded), only available if issuer was requested
     * @param issuerId              Issuer ID, only available if issuer was requested
     * @param issuerName            Issuer name, only available if issuer was requested
     */
    public record Data(
        @JsonProperty("authority_key_id") String authorityKeyId,
        @JsonProperty("certificate") String certificate,
        @JsonProperty("revocation_time") Long revocationTime,
        @JsonProperty("revocation_time_rfc3339") String revocationTimeRFC3339,
        @JsonProperty("ca_chain") List<String> caChain,
        @JsonProperty("issuer_id") String issuerId,
        @JsonProperty("issuer_name") String issuerName
    ) implements Serializable {
    }
}
