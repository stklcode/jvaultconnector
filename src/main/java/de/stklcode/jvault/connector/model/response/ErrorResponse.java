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

import java.util.List;

/**
 * Vault response in case of errors.
 *
 * @param errors List of errors
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 2.0 class is now a record
 */
public record ErrorResponse(List<String> errors) implements VaultResponse {

    @Override
    public String toString() {
        if (errors == null || errors.isEmpty()) {
            return "error response";
        } else {
            return errors.get(0);
        }
    }
}
