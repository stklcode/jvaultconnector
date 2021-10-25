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
import com.fasterxml.jackson.annotation.JsonProperty;
import de.stklcode.jvault.connector.model.response.embedded.TokenData;

import java.util.Objects;

/**
 * Vault response from token lookup providing Token information in {@link TokenData} field.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class TokenResponse extends VaultDataResponse {
    private static final long serialVersionUID = -4053126653764241197L;

    @JsonProperty("data")
    private TokenData data;

    @JsonProperty("auth")
    private Boolean auth;

    /**
     * @return Token data
     */
    public TokenData getData() {
        return data;
    }

    /**
     * @return Auth data
     */
    public Boolean getAuth() {
        return auth;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        TokenResponse that = (TokenResponse) o;
        return Objects.equals(data, that.data) && Objects.equals(auth, that.auth);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), data, auth);
    }
}
