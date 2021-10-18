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

import java.util.Objects;

/**
 * Vault response for health query.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class HealthResponse implements VaultResponse {
    private static final long serialVersionUID = 6483840078694294401L;

    @JsonProperty("cluster_id")
    private String clusterID;

    @JsonProperty("cluster_name")
    private String clusterName;

    @JsonProperty("version")
    private String version;

    @JsonProperty("server_time_utc")
    private Long serverTimeUTC;

    @JsonProperty("standby")
    private Boolean standby;

    @JsonProperty("sealed")
    private Boolean sealed;

    @JsonProperty("initialized")
    private Boolean initialized;

    @JsonProperty("replication_performance_mode")
    private String replicationPerfMode;

    @JsonProperty("replication_dr_mode")
    private String replicationDrMode;

    @JsonProperty("performance_standby")
    private Boolean performanceStandby;

    /**
     * @return The Cluster ID.
     */
    public String getClusterID() {
        return clusterID;
    }

    /**
     * @return The Cluster name.
     */
    public String getClusterName() {
        return clusterName;
    }

    /**
     * @return Vault version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * @return Server time UTC (timestamp).
     */
    public Long getServerTimeUTC() {
        return serverTimeUTC;
    }

    /**
     * @return Server standby status.
     */
    public Boolean isStandby() {
        return standby;
    }

    /**
     * @return Server seal status.
     */
    public Boolean isSealed() {
        return sealed;
    }

    /**
     * @return Server initialization status.
     */
    public Boolean isInitialized() {
        return initialized;
    }

    /**
     * @return Replication performance mode of the active node (since Vault 0.9.2).
     * @since 0.8 (#21)
     */
    public String getReplicationPerfMode() {
        return replicationPerfMode;
    }

    /**
     * @return Replication DR mode of the active node (since Vault 0.9.2).
     * @since 0.8 (#21)
     */
    public String getReplicationDrMode() {
        return replicationDrMode;
    }

    /**
     * @return Performance standby status.
     * @since 0.8 (#21)
     */
    public Boolean isPerformanceStandby() {
        return performanceStandby;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HealthResponse that = (HealthResponse) o;
        return Objects.equals(clusterID, that.clusterID) &&
                Objects.equals(clusterName, that.clusterName) &&
                Objects.equals(version, that.version) &&
                Objects.equals(serverTimeUTC, that.serverTimeUTC) &&
                Objects.equals(standby, that.standby) &&
                Objects.equals(sealed, that.sealed) &&
                Objects.equals(initialized, that.initialized) &&
                Objects.equals(replicationPerfMode, that.replicationPerfMode) &&
                Objects.equals(replicationDrMode, that.replicationDrMode) &&
                Objects.equals(performanceStandby, that.performanceStandby);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clusterID, clusterName, version, serverTimeUTC, standby, sealed, initialized,
                replicationPerfMode, replicationDrMode, performanceStandby);
    }
}
