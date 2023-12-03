package de.stklcode.jvault.connector.model.response.embedded;

import com.fasterxml.jackson.core.JsonProcessingException;
import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link MountConfig}.
 *
 * @author Stefan Kalscheuer
 */
class MountConfigTest extends AbstractModelTest<MountConfig> {
    private static final Integer DEFAULT_LEASE_TTL = 1800;
    private static final Integer MAX_LEASE_TTL = 3600;
    private static final Boolean FORCE_NO_CACHE = false;
    private static final String TOKEN_TYPE = "default-service";
    private static final String AUDIT_NON_HMAC_REQ_KEYS_1 = "req1";
    private static final String AUDIT_NON_HMAC_REQ_KEYS_2 = "req2";
    private static final String AUDIT_NON_HMAC_RES_KEYS_1 = "res1";
    private static final String AUDIT_NON_HMAC_RES_KEYS_2 = "res2";
    private static final String LISTING_VISIBILITY = "unauth";
    private static final String PT_REQ_HEADER_1 = "prh1";
    private static final String PT_REQ_HEADER_2 = "prh2";
    private static final String ALLOWED_RES_HEADER_1 = "arh1";
    private static final String ALLOWED_RES_HEADER_2 = "arh2";
    private static final String ALLOWED_MANAGED_KEY_1 = "amk1";
    private static final String ALLOWED_MANAGED_KEY_2 = "amk2";
    private static final String DEL_AUTH_ACCESSOR_1 = "daa1";
    private static final String DEL_AUTH_ACCESSOR_2 = "daa2";
    private static final Integer LOCKOUT_THRESH = 7200;
    private static final Integer LOCKOUT_DURATION = 86400;
    private static final Integer LOCKOUT_CNT_RESET_DURATION = 43200;
    private static final Boolean LOCKOUT_DISABLE = false;

    private static final String RES_JSON = "{\n" +
        "  \"default_lease_ttl\": " + DEFAULT_LEASE_TTL + ",\n" +
        "  \"force_no_cache\": " + FORCE_NO_CACHE + ",\n" +
        "  \"max_lease_ttl\": " + MAX_LEASE_TTL + ",\n" +
        "  \"token_type\": \"" + TOKEN_TYPE + "\",\n" +
        "  \"audit_non_hmac_request_keys\": [\"" + AUDIT_NON_HMAC_REQ_KEYS_1 + "\", \"" + AUDIT_NON_HMAC_REQ_KEYS_2 + "\"],\n" +
        "  \"audit_non_hmac_response_keys\": [\"" + AUDIT_NON_HMAC_RES_KEYS_1 + "\", \"" + AUDIT_NON_HMAC_RES_KEYS_2 + "\"],\n" +
        "  \"listing_visibility\": \"" + LISTING_VISIBILITY + "\",\n" +
        "  \"passthrough_request_headers\": [\"" + PT_REQ_HEADER_1 + "\", \"" + PT_REQ_HEADER_2 + "\"],\n" +
        "  \"allowed_response_headers\": [\"" + ALLOWED_RES_HEADER_1 + "\", \"" + ALLOWED_RES_HEADER_2 + "\"],\n" +
        "  \"allowed_managed_keys\": [\"" + ALLOWED_MANAGED_KEY_1 + "\", \"" + ALLOWED_MANAGED_KEY_2 + "\"],\n" +
        "  \"delegated_auth_accessors\": [\"" + DEL_AUTH_ACCESSOR_1 + "\", \"" + DEL_AUTH_ACCESSOR_2 + "\"],\n" +
        "  \"user_lockout_config\": {\n" +
        "    \"lockout_threshold\": " + LOCKOUT_THRESH + ",\n" +
        "    \"lockout_duration\": " + LOCKOUT_DURATION + ",\n" +
        "    \"lockout_counter_reset_duration\": " + LOCKOUT_CNT_RESET_DURATION + ",\n" +
        "    \"lockout_disable\": " + LOCKOUT_DISABLE + "\n" +
        "  }\n" +
        "}";

    MountConfigTest() {
        super(MountConfig.class);
    }

    @Override
    protected MountConfig createFull() {
        try {
            return objectMapper.readValue(RES_JSON, MountConfig.class);
        } catch (JsonProcessingException e) {
            fail("Creation of full model instance failed", e);
            return null;
        }
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    void jsonRoundtrip() {
        MountConfig mountConfig = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_JSON, MountConfig.class),
            "MountConfig deserialization failed"
        );
        assertNotNull(mountConfig, "Parsed response is NULL");

        // Verify data.
        assertEquals(DEFAULT_LEASE_TTL, mountConfig.getDefaultLeaseTtl(), "Unexpected default lease TTL");
        assertEquals(MAX_LEASE_TTL, mountConfig.getMaxLeaseTtl(), "Unexpected max lease TTL");
        assertEquals(FORCE_NO_CACHE, mountConfig.getForceNoCache(), "Unexpected force no cache");
        assertEquals(TOKEN_TYPE, mountConfig.getTokenType(), "Unexpected token type");
        assertEquals(List.of(AUDIT_NON_HMAC_REQ_KEYS_1, AUDIT_NON_HMAC_REQ_KEYS_2), mountConfig.getAuditNonHmacRequestKeys(), "Unexpected audit no HMAC request keys");
        assertEquals(List.of(AUDIT_NON_HMAC_RES_KEYS_1, AUDIT_NON_HMAC_RES_KEYS_2), mountConfig.getAuditNonHmacResponseKeys(), "Unexpected audit no HMAC response keys");
        assertEquals(LISTING_VISIBILITY, mountConfig.getListingVisibility(), "Unexpected listing visibility");
        assertEquals(List.of(PT_REQ_HEADER_1, PT_REQ_HEADER_2), mountConfig.getPassthroughRequestHeaders(), "Unexpected passthrough request headers");
        assertEquals(List.of(ALLOWED_RES_HEADER_1, ALLOWED_RES_HEADER_2), mountConfig.getAllowedResponseHeaders(), "Unexpected allowed response headers");
        assertEquals(List.of(ALLOWED_MANAGED_KEY_1, ALLOWED_MANAGED_KEY_2), mountConfig.getAllowedManagedKeys(), "Unexpected allowed managed keys");
        assertEquals(List.of(DEL_AUTH_ACCESSOR_1, DEL_AUTH_ACCESSOR_2), mountConfig.getDelegatedAuthAccessors(), "Unexpected delegate auth accessors");
        assertNotNull(mountConfig.getUserLockoutConfig(), "Missing user lockout config");
        var ulc = mountConfig.getUserLockoutConfig();
        assertEquals(LOCKOUT_THRESH, ulc.getLockoutThreshold(), "Unexpected lockout threshold");
        assertEquals(LOCKOUT_DURATION, ulc.getLockoutDuration(), "Unexpected lockout duration");
        assertEquals(LOCKOUT_CNT_RESET_DURATION, ulc.getLockoutCounterResetDuration(), "Unexpected lockout counter reset duration");
        assertEquals(LOCKOUT_DISABLE, ulc.getLockoutDisable(), "Unexpected lockout disable");
    }
}
