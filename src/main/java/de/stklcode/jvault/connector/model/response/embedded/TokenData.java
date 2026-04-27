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
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

/**
 * Embedded token information inside Vault response.
 *
 * @param accessor       Token accessor
 * @param creationTime   Creation time
 * @param creationTtl    Creation TTL (in seconds)
 * @param displayName    Token name
 * @param entityId       Entity ID
 * @param expireTime     Expire time
 * @param explicitMaxTtl Explicit maximum TTL (in seconds)
 * @param id             Token ID
 * @param issueTime      Issue time
 * @param meta           Metadata
 * @param numUses        Number of uses
 * @param orphan         Token is orphan
 * @param path           Token path
 * @param policies       Token policies
 * @param renewable      Token is renewable
 * @param ttl            Token TTL (in seconds)
 * @param type           Token type
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 1.1 implements {@link Serializable}
 * @since 2.0 class is now a record
 */
public record TokenData(
    String accessor,
    Integer creationTime,
    Long creationTtl,
    String displayName,
    String entityId,
    ZonedDateTime expireTime,
    Long explicitMaxTtl,
    String id,
    ZonedDateTime issueTime,
    Map<String, Object> meta,
    Integer numUses,
    boolean orphan,
    String path,
    List<String> policies,
    Boolean renewable,
    Long ttl,
    String type
) implements Serializable {
}
