package de.stklcode.jvault.connector.model.response.embedded;

import java.io.Serializable;
import java.util.List;

/**
 * Wrapper object for secret key lists.
 *
 * @param keys List of secret keys
 * @author Stefan Kalscheuer
 * @since 1.1
 * @since 2.0 class is now a record
 */
public record SecretListWrapper(List<String> keys) implements Serializable {
}
