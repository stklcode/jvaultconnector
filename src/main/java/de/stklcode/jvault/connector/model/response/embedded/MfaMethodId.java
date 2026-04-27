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

package de.stklcode.jvault.connector.model.response.embedded;

import java.io.Serializable;

/**
 * Embedded multi-factor-authentication (MFA) requirement.
 *
 * @param type         MFA method type
 * @param id           MFA method ID
 * @param usesPasscode MFA uses passcode id
 * @param name         MFA method name
 * @author Stefan Kalscheuer
 * @since 1.2
 * @since 2.0 class is now a record
 */
public record MfaMethodId(
    String type,
    String id,
    Boolean usesPasscode,
    String name
) implements Serializable {
}
