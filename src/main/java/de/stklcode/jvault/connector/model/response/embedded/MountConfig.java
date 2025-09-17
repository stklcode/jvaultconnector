package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Embedded mount config output.
 *
 * @author Stefan Kalscheuer
 * @since 1.2
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MountConfig implements Serializable {
    @Serial
    private static final long serialVersionUID = 7241631159224756605L;

    @JsonProperty("default_lease_ttl")
    private Long defaultLeaseTtl;

    @JsonProperty("max_lease_ttl")
    private Long maxLeaseTtl;

    @JsonProperty("force_no_cache")
    private Boolean forceNoCache;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("audit_non_hmac_request_keys")
    private List<String> auditNonHmacRequestKeys;

    @JsonProperty("audit_non_hmac_response_keys")
    private List<String> auditNonHmacResponseKeys;

    @JsonProperty("listing_visibility")
    private String listingVisibility;

    @JsonProperty("passthrough_request_headers")
    private List<String> passthroughRequestHeaders;

    @JsonProperty("allowed_response_headers")
    private List<String> allowedResponseHeaders;

    @JsonProperty("allowed_managed_keys")
    private List<String> allowedManagedKeys;

    @JsonProperty("delegated_auth_accessors")
    private List<String> delegatedAuthAccessors;

    @JsonProperty("user_lockout_config")
    private UserLockoutConfig userLockoutConfig;

    /**
     * @return Default lease TTL
     */
    public Long getDefaultLeaseTtl() {
        return defaultLeaseTtl;
    }

    /**
     * @return Maximum lease TTL
     */
    public Long getMaxLeaseTtl() {
        return maxLeaseTtl;
    }

    /**
     * @return Force no cache?
     */
    public Boolean getForceNoCache() {
        return forceNoCache;
    }

    /**
     * @return Token type
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * @return Audit non HMAC request keys
     */
    public List<String> getAuditNonHmacRequestKeys() {
        return auditNonHmacRequestKeys;
    }

    /**
     * @return Audit non HMAC response keys
     */
    public List<String> getAuditNonHmacResponseKeys() {
        return auditNonHmacResponseKeys;
    }

    /**
     * @return Listing visibility
     */
    public String getListingVisibility() {
        return listingVisibility;
    }

    /**
     * @return Passthrough request headers
     */
    public List<String> getPassthroughRequestHeaders() {
        return passthroughRequestHeaders;
    }

    /**
     * @return Allowed response headers
     */
    public List<String> getAllowedResponseHeaders() {
        return allowedResponseHeaders;
    }

    /**
     * @return Allowed managed keys
     */
    public List<String> getAllowedManagedKeys() {
        return allowedManagedKeys;
    }

    /**
     * @return Delegated auth accessors
     */
    public List<String> getDelegatedAuthAccessors() {
        return delegatedAuthAccessors;
    }

    /**
     * @return User lockout config
     */
    public UserLockoutConfig getUserLockoutConfig() {
        return userLockoutConfig;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MountConfig that = (MountConfig) o;
        return Objects.equals(defaultLeaseTtl, that.defaultLeaseTtl) &&
            Objects.equals(maxLeaseTtl, that.maxLeaseTtl) &&
            Objects.equals(forceNoCache, that.forceNoCache) &&
            Objects.equals(tokenType, that.tokenType) &&
            Objects.equals(auditNonHmacRequestKeys, that.auditNonHmacRequestKeys) &&
            Objects.equals(auditNonHmacResponseKeys, that.auditNonHmacResponseKeys) &&
            Objects.equals(listingVisibility, that.listingVisibility) &&
            Objects.equals(passthroughRequestHeaders, that.passthroughRequestHeaders) &&
            Objects.equals(allowedResponseHeaders, that.allowedResponseHeaders) &&
            Objects.equals(allowedManagedKeys, that.allowedManagedKeys) &&
            Objects.equals(delegatedAuthAccessors, that.delegatedAuthAccessors) &&
            Objects.equals(userLockoutConfig, that.userLockoutConfig);
    }

    @Override
    public int hashCode() {
        return Objects.hash(defaultLeaseTtl, maxLeaseTtl, forceNoCache, tokenType, auditNonHmacRequestKeys,
            auditNonHmacResponseKeys, listingVisibility, passthroughRequestHeaders, allowedResponseHeaders,
            allowedManagedKeys, delegatedAuthAccessors, userLockoutConfig);
    }
}
