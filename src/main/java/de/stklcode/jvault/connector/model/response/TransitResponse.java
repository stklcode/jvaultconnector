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

import com.fasterxml.jackson.annotation.JsonSetter;

import java.io.Serial;
import java.util.Map;
import java.util.Objects;

/**
 * Response entity for transit operations.
 *
 * @author Stefan Kalscheuer
 * @since 1.5.0
 */
public class TransitResponse extends VaultDataResponse {

    @Serial
    private static final long serialVersionUID = 6873804240772242771L;

    private String ciphertext;
    private String plaintext;
    private String sum;

    @JsonSetter("data")
    private void setData(Map<String, String> data) {
        ciphertext = data.get("ciphertext");
        plaintext = data.get("plaintext");
        sum = data.get("sum");
    }

    /**
     * Get ciphertext.
     * Populated after encryption.
     *
     * @return Ciphertext
     */
    public String getCiphertext() {
        return ciphertext;
    }

    /**
     * Get plaintext.
     * Base64 encoded, populated after decryption.
     *
     * @return Plaintext
     */
    public String getPlaintext() {
        return plaintext;
    }

    /**
     * Get hash sum.
     * Hex or Base64 string. Populated after hashing.
     *
     * @return Hash sum
     */
    public String getSum() {
        return sum;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        TransitResponse that = (TransitResponse) o;
        return Objects.equals(ciphertext, that.ciphertext) &&
            Objects.equals(plaintext, that.plaintext) &&
            Objects.equals(sum, that.sum);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), ciphertext, plaintext, sum);
    }
}
