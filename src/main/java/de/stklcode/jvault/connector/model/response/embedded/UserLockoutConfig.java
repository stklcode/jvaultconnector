package de.stklcode.jvault.connector.model.response.embedded;

import java.io.Serializable;

/**
 * Embedded user lockout config output.
 *
 * @param lockoutThreshold            Lockout threshold
 * @param lockoutDuration             Lockout duration
 * @param lockoutCounterResetDuration Lockout counter reset duration
 * @param lockoutDisable              Lockout disabled?
 * @author Stefan Kalscheuer
 * @since 1.2
 * @since 2.0 class is now a record
 */
public record UserLockoutConfig(
    Integer lockoutThreshold,
    Integer lockoutDuration,
    Integer lockoutCounterResetDuration,
    Boolean lockoutDisable
) implements Serializable {
}
