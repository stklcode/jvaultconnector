package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.fail;

;

/**
 * JUnit Test for {@link AuthResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.7.0
 */
public class HealthResponseTest {
    private static final String CLUSTER_ID = "c9abceea-4f46-4dab-a688-5ce55f89e228";
    private static final String CLUSTER_NAME = "vault-cluster-5515c810";
    private static final String VERSION = "0.6.2";
    private static final Long SERVER_TIME_UTC = 1469555798L;
    private static final Boolean STANDBY = false;
    private static final Boolean SEALED = false;
    private static final Boolean INITIALIZED = true;

    private static final String RES_JSON = "{\n" +
            "  \"cluster_id\": \"" + CLUSTER_ID + "\",\n" +
            "  \"cluster_name\": \"" + CLUSTER_NAME + "\",\n" +
            "  \"version\": \"" + VERSION + "\",\n" +
            "  \"server_time_utc\": " + SERVER_TIME_UTC + ",\n" +
            "  \"standby\": " + STANDBY + ",\n" +
            "  \"sealed\": " + SEALED + ",\n" +
            "  \"initialized\": " + INITIALIZED + "\n" +
            "}";
    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    public void jsonRoundtrip() {
        try {
            HealthResponse res = new ObjectMapper().readValue(RES_JSON, HealthResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            assertThat("Incorrect cluster ID", res.getClusterID(), is(CLUSTER_ID));
            assertThat("Incorrect cluster name", res.getClusterName(), is(CLUSTER_NAME));
            assertThat("Incorrect version", res.getVersion(), is(VERSION));
            assertThat("Incorrect server time", res.getServerTimeUTC(), is(SERVER_TIME_UTC));
            assertThat("Incorrect standby state", res.isStandby(), is(STANDBY));
            assertThat("Incorrect seal state", res.isSealed(), is(SEALED));
            assertThat("Incorrect initialization state", res.isInitialized(), is(INITIALIZED));
        } catch (IOException e) {
            fail("Health deserialization failed: " + e.getMessage());
        }
    }
}
