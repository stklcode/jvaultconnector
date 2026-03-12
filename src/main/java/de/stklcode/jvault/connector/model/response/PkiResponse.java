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
 * Vault response for PKI certificates.
 *
 * @param responseHeader Response metadata
 * @param data           PKI response data
 * @author Stefan Kalscheuer
 * @since 2.0.0
 */
public record PkiResponse(
    @JsonUnwrapped Header responseHeader,
    @JsonProperty("data") Data data
) implements VaultDataResponse {

    /**
     *
     * PKI data object.
     * @param expiration     Certificate expiration timestamp
     * @param certificate    Certificate (PEM encoded)
     * @param issuingCa      Issuing CA certificate (PEM or Base64 encoded)
     * @param caChain        Full CA certificate chain (PEM or Base64 encoded)
     * @param privateKey     Certificate private key (PEM or Base64 encoded)
     * @param privateKeyType Certificate private key type
     * @param serialNumber   Certificate serial number
     */
    public record Data(
        @JsonProperty("expiration") Long expiration,
        @JsonProperty("certificate") String certificate,
        @JsonProperty("issuing_ca") String issuingCa,
        @JsonProperty("ca_chain") List<String> caChain,
        @JsonProperty("private_key") String privateKey,
        @JsonProperty("private_key_type") String privateKeyType,
        @JsonProperty("serial_number") String serialNumber
    ) implements Serializable {
    }
}
