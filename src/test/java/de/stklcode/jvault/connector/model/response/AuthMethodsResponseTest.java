package de.stklcode.jvault.connector.model.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.InvalidResponseException;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.response.embedded.AuthData;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * JUnit Test for {@link AuthMethodsResponse} model.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
public class AuthMethodsResponseTest {
    private static final String GH_PATH = "github/";
    private static final String GH_TYPE = "github";
    private static final String GH_DESCR = "GitHub auth";
    private static final String TK_PATH = "token/";
    private static final String TK_TYPE = "token";
    private static final String TK_DESCR = "token based credentials";
    private static final Integer TK_LEASE_TTL = 0;
    private static final Integer TK_MAX_LEASE_TTL = 0;

    private static final String RES_JSON = "{\n" +
            "  \"data\": {" +
            "    \"" + GH_PATH + "\": {\n" +
            "      \"type\": \"" + GH_TYPE + "\",\n" +
            "      \"description\": \"" + GH_DESCR + "\"\n" +
            "    },\n" +
            "    \"" + TK_PATH + "\": {\n" +
            "      \"config\": {\n" +
            "        \"default_lease_ttl\": " + TK_LEASE_TTL + ",\n" +
            "        \"max_lease_ttl\": " + TK_MAX_LEASE_TTL + "\n" +
            "      },\n" +
            "      \"description\": \"" + TK_DESCR + "\",\n" +
            "      \"type\": \"" + TK_TYPE + "\"\n" +
            "    }\n" +
            "  }\n" +
            "}";

    private static final Map<String, Object> INVALID_DATA = new HashMap<>();

    static {
        INVALID_DATA.put("dummy/", new Dummy());
    }

    /**
     * Test getter, setter and get-methods for response data.
     */
    @Test
    public void getDataRoundtrip() {
        // Create empty Object.
        AuthMethodsResponse res = new AuthMethodsResponse();
        assertThat("Initial method map should be empty", res.getSupportedMethods(), is(anEmptyMap()));

        // Parsing invalid data map should fail.
        try {
            res.setData(INVALID_DATA);
            fail("Parsing invalid data succeeded");
        } catch (Exception e) {
            assertThat(e, is(instanceOf(InvalidResponseException.class)));
        }
    }

    /**
     * Test creation from JSON value as returned by Vault (JSON example copied from Vault documentation).
     */
    @Test
    public void jsonRoundtrip() {
        try {
            AuthMethodsResponse res = new ObjectMapper().readValue(RES_JSON, AuthMethodsResponse.class);
            assertThat("Parsed response is NULL", res, is(notNullValue()));
            // Extract auth data.
            Map<String, AuthMethod> supported = res.getSupportedMethods();
            assertThat("Auth data is NULL", supported, is(notNullValue()));
            assertThat("Incorrect number of supported methods", supported.entrySet(), hasSize(2));
            assertThat("Incorrect method paths", supported.keySet(), containsInAnyOrder(GH_PATH, TK_PATH));

            // Verify first method.
            AuthMethod method = supported.get(GH_PATH);
            assertThat("Incorrect raw type for GitHub", method.getRawType(), is(GH_TYPE));
            assertThat("Incorrect parsed type for GitHub", method.getType(), is(AuthBackend.GITHUB));
            assertThat("Incorrect description for GitHub", method.getDescription(), is(GH_DESCR));
            assertThat("Unexpected config for GitHub", method.getConfig(), is(nullValue()));

            // Verify first method.
            method = supported.get(TK_PATH);
            assertThat("Incorrect raw type for Token", method.getRawType(), is(TK_TYPE));
            assertThat("Incorrect parsed type for Token", method.getType(), is(AuthBackend.TOKEN));
            assertThat("Incorrect description for Token", method.getDescription(), is(TK_DESCR));
            assertThat("Missing config for Token", method.getConfig(), is(notNullValue()));
            assertThat("Unexpected config size for Token", method.getConfig().keySet(), hasSize(2));
            assertThat("Incorrect lease TTL config", method.getConfig().get("default_lease_ttl"), is(TK_LEASE_TTL.toString()));
            assertThat("Incorrect max lease TTL config", method.getConfig().get("max_lease_ttl"), is(TK_MAX_LEASE_TTL.toString()));
        } catch (IOException e) {
            fail("AuthResponse deserialization failed: " + e.getMessage());
        }
    }

    private static class Dummy {

    }
}
