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

package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;

import java.io.Serial;

/**
 * Vault response for authentication providing auth info in {@link AuthData} field.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuthResponse extends VaultDataResponse {
    @Serial
    private static final long serialVersionUID = 1628851361067456715L;
}
