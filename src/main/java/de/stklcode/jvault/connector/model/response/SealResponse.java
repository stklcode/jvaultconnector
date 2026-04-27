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

import java.time.ZonedDateTime;

/**
 * Vault response for seal status or unseal request.
 *
 * @param type           Seal type
 * @param sealed         Seal status
 * @param initialized    Vault initialization status (since Vault 0.11.2)
 * @param threshold      Required threshold of secret shares
 * @param numberOfShares Number of secret shares
 * @param progress       Current unseal progress (remaining required shares)
 * @param version        Vault version
 * @param buildDate      Vault build date
 * @param nonce          Random nonce
 * @param clusterName    Vault cluster name (only if unsealed)
 * @param clusterId      Vault cluster ID (only if unsealed)
 * @param migration      Migration status (since Vault 1.4)
 * @param recoverySeal   Recovery seal status
 * @param storageType    Storage type (since Vault 1.3)
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 2.0 class is now a record
 */
public record SealResponse(
    String type,
    boolean sealed,
    boolean initialized,
    @JsonProperty("t") Integer threshold,
    @JsonProperty("n") Integer numberOfShares,
    Integer progress,
    String version,
    ZonedDateTime buildDate,
    String nonce,
    String clusterName,
    String clusterId,
    Boolean migration,
    Boolean recoverySeal,
    String storageType
) implements VaultResponse {
}
