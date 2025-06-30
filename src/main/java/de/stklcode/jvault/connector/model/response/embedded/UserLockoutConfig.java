package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Embedded user lockout config output.
 *
 * @author Stefan Kalscheuer
 * @since 1.2
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserLockoutConfig implements Serializable {
    @Serial
    private static final long serialVersionUID = -8051060041593140550L;

    @JsonProperty("lockout_threshold")
    private Integer lockoutThreshold;

    @JsonProperty("lockout_duration")
    private Integer lockoutDuration;

    @JsonProperty("lockout_counter_reset_duration")
    private Integer lockoutCounterResetDuration;

    @JsonProperty("lockout_disable")
    private Boolean lockoutDisable;

    /**
     * @return Lockout threshold
     */
    public Integer getLockoutThreshold() {
        return lockoutThreshold;
    }

    /**
     * @return Lockout duration
     */
    public Integer getLockoutDuration() {
        return lockoutDuration;
    }

    /**
     * @return Lockout counter reset duration
     */
    public Integer getLockoutCounterResetDuration() {
        return lockoutCounterResetDuration;
    }

    /**
     * @return Lockout disabled?
     */
    public Boolean getLockoutDisable() {
        return lockoutDisable;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserLockoutConfig that = (UserLockoutConfig) o;
        return Objects.equals(lockoutThreshold, that.lockoutThreshold) &&
            Objects.equals(lockoutDuration, that.lockoutDuration) &&
            Objects.equals(lockoutCounterResetDuration, that.lockoutCounterResetDuration) &&
            Objects.equals(lockoutDisable, that.lockoutDisable);
    }

    @Override
    public int hashCode() {
        return Objects.hash(lockoutThreshold, lockoutDuration, lockoutCounterResetDuration, lockoutDisable);
    }
}
