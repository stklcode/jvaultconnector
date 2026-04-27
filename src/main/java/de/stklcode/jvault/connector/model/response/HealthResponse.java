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

/**
 * Vault response for health query
 *
 * @param clusterID                     The Cluster ID
 * @param clusterName                   The Cluster name
 * @param version                       Vault version
 * @param serverTimeUTC                 Server time UTC (timestamp)
 * @param standby                       Server standby status
 * @param sealed                        Server seal status
 * @param initialized                   Server initialization status
 * @param replicationPerformanceMode    Replication performance mode of the active node (since Vault 0.9.2)
 * @param replicationDrMode             Replication DR mode of the active node (since Vault 0.9.2)
 * @param performanceStandby            Performance standby status
 * @param echoDurationMs                Heartbeat echo duration in milliseconds (since Vault 1.16)
 * @param clockSkewMs                   Clock skew in milliseconds (since Vault 1.16)
 * @param replicationPrimaryCanaryAgeMs Replication primary canary age in milliseconds (since Vault 1.17)
 * @param enterprise                    Enterprise instance? (since Vault 1.17)
 * @author Stefan Kalscheuer
 * @since 0.7.0
 * @since 2.0 class is now a record
 */
public record HealthResponse(
    String clusterID,
    String clusterName,
    String version,
    Long serverTimeUTC,
    Boolean standby,
    Boolean sealed,
    Boolean initialized,
    String replicationPerformanceMode,
    String replicationDrMode,
    Boolean performanceStandby,
    Long echoDurationMs,
    Long clockSkewMs,
    Long replicationPrimaryCanaryAgeMs,
    Boolean enterprise
) implements VaultResponse {
}
