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

package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import de.stklcode.jvault.connector.model.AuthBackend;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;

/**
 * Embedded authentication method response.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 1.1 implements {@link Serializable}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuthMethod implements Serializable {
    private static final long serialVersionUID = -2718660627880077335L;

    private AuthBackend type;
    private String rawType;

    @JsonProperty("accessor")
    private String accessor;

    @JsonProperty("description")
    private String description;

    @JsonProperty("config")
    private Map<String, String> config;

    @JsonProperty("external_entropy_access")
    private boolean externalEntropyAccess;

    @JsonProperty("local")
    private boolean local;

    @JsonProperty("seal_wrap")
    private boolean sealWrap;

    @JsonProperty("uuid")
    private String uuid;

    /**
     * @param type Backend type, passed to {@link AuthBackend#forType(String)}
     */
    @JsonSetter("type")
    public void setType(final String type) {
        this.rawType = type;
        this.type = AuthBackend.forType(type);
    }

    /**
     * @return Backend type
     */
    public AuthBackend getType() {
        return type;
    }

    /**
     * @return Raw backend type string
     */
    public String getRawType() {
        return rawType;
    }

    /**
     * @return Accessor
     * @since 1.1
     */
    public String getAccessor() {
        return accessor;
    }

    /**
     * @return Description
     */
    public String getDescription() {
        return description;
    }

    /**
     * @return Configuration data
     */
    public Map<String, String> getConfig() {
        return config;
    }

    /**
     * @return Backend has access to external entropy source
     * @since 1.1
     */
    public boolean isExternalEntropyAccess() {
        return externalEntropyAccess;
    }

    /**
     * @return Is local backend
     */
    public boolean isLocal() {
        return local;
    }

    /**
     * @return Seal wrapping enabled
     * @since 1.1
     */
    public boolean isSealWrap() {
        return sealWrap;
    }

    /**
     * @return Backend UUID
     * @since 1.1
     */
    public String getUuid() {
        return uuid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthMethod that = (AuthMethod) o;
        return local == that.local &&
                type == that.type &&
                externalEntropyAccess == that.externalEntropyAccess &&
                sealWrap == that.sealWrap &&
                Objects.equals(rawType, that.rawType) &&
                Objects.equals(accessor, that.accessor) &&
                Objects.equals(description, that.description) &&
                Objects.equals(config, that.config) &&
                Objects.equals(uuid, that.uuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, rawType, accessor, description, config, externalEntropyAccess, local, sealWrap, uuid);
    }
}
