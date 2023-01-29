/*
 * Copyright 2016-2023 Stefan Kalscheuer
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

package de.stklcode.jvault.connector.model;

/**
 * Currently supported authentication backends.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public enum AuthBackend {
    TOKEN("token"),
    @Deprecated(since = "1.1.3", forRemoval = true)
    APPID("app-id"),
    APPROLE("approle"),
    USERPASS("userpass"),
    GITHUB("github"),   // Not supported yet.
    UNKNOWN("");

    private final String type;

    /**
     * Construct {@link AuthBackend} of given type.
     *
     * @param type Backend type
     */
    AuthBackend(final String type) {
        this.type = type;
    }

    /**
     * Retrieve {@link AuthBackend} value for given type string.
     *
     * @param type Type string
     * @return Auth backend value
     */
    public static AuthBackend forType(final String type) {
        for (AuthBackend v : values()) {
            if (v.type.equalsIgnoreCase(type)) {
                return v;
            }
        }
        return UNKNOWN;
    }
}
