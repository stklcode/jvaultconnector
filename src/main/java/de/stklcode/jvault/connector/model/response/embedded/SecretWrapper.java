package de.stklcode.jvault.connector.model.response.embedded;

import java.io.Serializable;
import java.util.Map;

/**
 * Wrapper object for secret data and metadata.
 *
 * @param data     Secret data
 * @param metadata Secret Metadata
 * @author Stefan Kalscheuer
 * @since 1.1
 * @since 2.0 class is now a record
 */
public record SecretWrapper(
    Map<String, Serializable> data,

    VersionMetadata metadata
) implements Serializable {
}
