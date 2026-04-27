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

import java.io.Serializable;

/**
 * Response entity for transit operations.
 *
 * @param responseHeader Response metadata
 * @param data           Transit data wrapper
 * @author Stefan Kalscheuer
 * @since 1.5.0
 * @since 2.0 class is now a record
 */
public record TransitResponse(
    @JsonUnwrapped Header responseHeader,
    Data data
) implements VaultDataResponse {

    /**
     * Get ciphertext.
     * Populated after encryption.
     *
     * @return Ciphertext
     */
    public String ciphertext() {
        if (data != null) {
            return data.ciphertext();
        }
        return null;
    }

    /**
     * Get plaintext.
     * Base64 encoded, populated after decryption.
     *
     * @return Plaintext
     */
    public String plaintext() {
        if (data != null) {
            return data.plaintext();
        }
        return null;
    }

    /**
     * Get hash sum.
     * Hex or Base64 string. Populated after hashing.
     *
     * @return Hash sum
     */
    public String sum() {
        if (data != null) {
            return data.sum();
        }
        return null;
    }

    /**
     * Transit response data model.
     *
     * @param ciphertext Ciphertext
     * @param plaintext  Plaintext
     * @param sum        Hash sum
     * @since 2.0
     */
    public record Data(
        String ciphertext,
        String plaintext,
        String sum
    ) implements Serializable {
    }
}
