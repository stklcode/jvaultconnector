/*
 * Copyright 2016-2019 Stefan Kalscheuer
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

/**
 * Vault response for seal status or unseal request.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class SealResponse implements VaultResponse {
    @JsonProperty("type")
    private String type;

    @JsonProperty("sealed")
    private boolean sealed;

    @JsonProperty("initialized")
    private boolean initialized;

    @JsonProperty("t")
    private Integer threshold;

    @JsonProperty("n")
    private Integer numberOfShares;

    @JsonProperty("progress")
    private Integer progress;

    @JsonProperty("version")
    private String version;

    @JsonProperty("nonce")
    private String nonce;

    @JsonProperty("cluster_name")
    private String clusterName;

    @JsonProperty("cluster_id")
    private String clusterId;

    /**
     * @return Seal type.
     * @since 0.8
     */
    public String getType() {
        return type;
    }

    /**
     * @return Seal status
     */
    public boolean isSealed() {
        return sealed;
    }

    /**
     * @return Vault initialization status (since Vault 0.11.2).
     * @since 0.8
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * @return Required threshold of secret shares
     */
    public Integer getThreshold() {
        return threshold;
    }

    /**
     * @return Number of secret shares
     */
    public Integer getNumberOfShares() {
        return numberOfShares;
    }

    /**
     * @return Current unseal progress (remaining required shares)
     */
    public Integer getProgress() {
        return progress;
    }

    /**
     * @return Vault version.
     * @since 0.8
     */
    public String getVersion() {
        return version;
    }

    /**
     * @return A random nonce.
     * @since 0.8
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * @return Vault cluster name (only if unsealed).
     * @since 0.8
     */
    public String getClusterName() {
        return clusterName;
    }

    /**
     * @return Vault cluster ID (only if unsealed).
     * @since 0.8
     */
    public String getClusterId() {
        return clusterId;
    }
}
