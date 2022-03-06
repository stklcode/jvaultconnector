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

package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wrapping information object.
 *
 * @author Stefan Kalscheuer
 * @since 1.1
 */
public class WrapInfo {

    @JsonProperty("token")
    private String token;

    @JsonProperty("ttl")
    private Integer ttl;

    @JsonProperty("creation_time")
    private String creationTime;

    @JsonProperty("creation_path")
    private String creationPath;

    /**
     * @return Token
     */
    public String getToken() {
        return token;
    }

    /**
     * @return TTL (in seconds)
     */
    public Integer getTtl() {
        return ttl;
    }

    /**
     * @return Creation time
     */
    public String getCreationTime() {
        return creationTime;
    }

    /**
     * @return Creation path
     */
    public String getCreationPath() {
        return creationPath;
    }
}
