package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Embedded token information inside Vault response.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenData {
    @JsonProperty("accessor")
    private String accessor;

    @JsonProperty("creation_time")
    private Integer creationTime;

    @JsonProperty("creation_ttl")
    private Integer creatinTtl;

    @JsonProperty("display_name")
    private String name;

    @JsonProperty("id")
    private String id;

    @JsonProperty("meta")
    private String meta;

    @JsonProperty("num_uses")
    private Integer numUses;

    @JsonProperty("orphan")
    private boolean orphan;

    @JsonProperty("path")
    private String path;

    @JsonProperty("role")
    private String role;

    @JsonProperty("ttl")
    private Integer ttl;

    public String getAccessor() {
        return accessor;
    }

    public Integer getCreationTime() {
        return creationTime;
    }

    public Integer getCreatinTtl() {
        return creatinTtl;
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public Integer getNumUses() {
        return numUses;
    }

    public boolean isOrphan() {
        return orphan;
    }

    public String getPath() {
        return path;
    }

    public String getRole() {
        return role;
    }

    public Integer getTtl() {
        return ttl;
    }

    public String getMeta() {
        return meta;
    }
}