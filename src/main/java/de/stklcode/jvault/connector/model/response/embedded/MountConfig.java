package de.stklcode.jvault.connector.model.response.embedded;

import java.io.Serializable;
import java.util.List;

/**
 * Embedded mount config output.
 *
 * @param defaultLeaseTtl           Default lease TTL
 * @param maxLeaseTtl               Maximum lease TTL
 * @param forceNoCache              Force no cache?
 * @param tokenType                 Token type
 * @param auditNonHmacRequestKeys   Audit non-HMAC request keys
 * @param auditNonHmacResponseKeys  Audit non-HMAC response keys
 * @param listingVisibility         Listing visibility
 * @param passthroughRequestHeaders Passthrough request headers
 * @param allowedResponseHeaders    Allowed response headers
 * @param allowedManagedKeys        Allowed managed keys
 * @param delegatedAuthAccessors    Delegated auth accessors
 * @param userLockoutConfig         User lockout config
 * @author Stefan Kalscheuer
 * @since 1.2
 * @since 2.0 class is now a record
 */
public record MountConfig(
    Long defaultLeaseTtl,
    Long maxLeaseTtl,
    Boolean forceNoCache,
    String tokenType,
    List<String> auditNonHmacRequestKeys,
    List<String> auditNonHmacResponseKeys,
    String listingVisibility,
    List<String> passthroughRequestHeaders,
    List<String> allowedResponseHeaders,
    List<String> allowedManagedKeys,
    List<String> delegatedAuthAccessors,
    UserLockoutConfig userLockoutConfig
) implements Serializable {
}
