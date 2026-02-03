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

package de.stklcode.jvault.connector.internal;

/**
 * Vault API path constants.
 *
 * @author Stefan Kalscheuer
 * @since 1.5.3
 */
public final class VaultApiPath {
    // Base paths
    private static final String SYS = "sys";
    private static final String AUTH = "auth";
    private static final String TRANSIT = "transit";

    // System paths
    public static final String SYS_AUTH = SYS + "/auth";
    public static final String SYS_LEASES_RENEW = SYS + "/leases/renew";
    public static final String SYS_LEASES_REVOKE = SYS + "/leases/revoke/";
    public static final String SYS_HEALTH = SYS + "/health";
    public static final String SYS_SEAL = SYS + "/seal";
    public static final String SYS_SEAL_STATUS = SYS + "/seal-status";
    public static final String SYS_UNSEAL = SYS + "/unseal";

    // Auth paths
    public static final String AUTH_TOKEN = AUTH + "/token";
    public static final String AUTH_USERPASS_LOGIN = AUTH + "/userpass/login/";
    public static final String AUTH_APPROLE = AUTH + "/approle/";
    public static final String AUTH_APPROLE_ROLE = AUTH_APPROLE + "role/";

    // Token operations
    public static final String TOKEN_LOOKUP = "/lookup";
    public static final String TOKEN_LOOKUP_SELF = "/lookup-self";
    public static final String TOKEN_CREATE = "/create";
    public static final String TOKEN_CREATE_ORPHAN = "/create-orphan";
    public static final String TOKEN_ROLES = "/roles";

    // Secret engine paths
    public static final String SECRET_DATA = "/data/";
    public static final String SECRET_METADATA = "/metadata/";
    public static final String SECRET_DELETE = "/delete/";
    public static final String SECRET_UNDELETE = "/undelete/";
    public static final String SECRET_DESTROY = "/destroy/";

    // Transit engine paths
    public static final String TRANSIT_ENCRYPT = TRANSIT + "/encrypt/";
    public static final String TRANSIT_DECRYPT = TRANSIT + "/decrypt/";
    public static final String TRANSIT_HASH = TRANSIT + "/hash/";

    /**
     * Private constructor to prevent instantiation.
     */
    private VaultApiPath() {
        // Utility class
    }
}
