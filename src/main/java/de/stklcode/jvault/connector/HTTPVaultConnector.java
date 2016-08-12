package de.stklcode.jvault.connector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HTTP;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Vault Connector implementatin using Vault's HTTP API.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public class HTTPVaultConnector implements VaultConnector {
    private static final String PATH_PREFIX =        "/v1/";
    private static final String PATH_SEAL_STATUS =   "sys/seal-status";
    private static final String PATH_SEAL =          "sys/seal";
    private static final String PATH_UNSEAL =        "sys/unseal";
    private static final String PATH_INIT =          "sys/init";
    private static final String PATH_AUTH =          "sys/auth";
    private static final String PATH_TOKEN_LOOKUP =  "auth/token/lookup";
    private static final String PATH_AUTH_USERPASS = "auth/userpass/login/";
    private static final String PATH_AUTH_APPID =    "auth/app-id/";
    private static final String PATH_SECRET =        "secret";

    private final ObjectMapper jsonMapper;

    private final HttpClient httpClient;        /* HTTP client for connection */
    private final String baseURL;               /* Base URL of Vault */

    private boolean authorized = false;         /* authorization status */
    private String token;                       /* current token */

    /**
     * Create connector using hostname and schema.
     * @param hostname  The hostname
     * @param useTLS    If TRUE, use HTTPS, otherwise HTTP
     */
    public HTTPVaultConnector(String hostname, boolean useTLS) {
        this(hostname, useTLS, null);
    }

    /**
     * Create connector using hostname, schema and port.
     * @param hostname  The hostname
     * @param useTLS    If TRUE, use HTTPS, otherwise HTTP
     * @param port      The port
     */
    public HTTPVaultConnector(String hostname, boolean useTLS, Integer port) {
        this(hostname, useTLS, port, PATH_PREFIX);
    }

    /**
     * Create connector using hostname, schame, port and path
     * @param hostname  The hostname
     * @param useTLS    If TRUE, use HTTPS, otherwise HTTP
     * @param port      The port
     * @param prefix    HTTP API prefix (default: /v1/"
     */
    public HTTPVaultConnector(String hostname, boolean useTLS, Integer port, String prefix) {
        this(((useTLS) ? "https" : "http") +
                "://" + hostname +
                ((port != null) ? ":" + port : "") +
                prefix);
    }

    /**
     * Create connector using full URL
     * @param baseURL   The URL
     */
    public HTTPVaultConnector(String baseURL) {
        this.baseURL = baseURL;
        this.httpClient = new DefaultHttpClient();
        this.jsonMapper = new ObjectMapper();
    }

    @Override
    public void resetAuth() {
        token = null;
        authorized = false;
    }

    @Override
    public SealResponse sealStatus() {
        try {
            String response = requestGet(PATH_SEAL_STATUS, new HashMap<>());
            return jsonMapper.readValue(response, SealResponse.class);
        } catch (VaultConnectorException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean seal() {
        try {
            requestPut(PATH_SEAL, new HashMap<>());
            return true;
        } catch (VaultConnectorException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public SealResponse unseal(final String key, final Boolean reset) {
        Map<String, Object> param = new HashMap<>();
        param.put("key", key);
        if (reset != null)
            param.put("reset", reset);
        try {
            String response = requestPut(PATH_UNSEAL, param);
            return jsonMapper.readValue(response, SealResponse.class);
        } catch (VaultConnectorException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean isAuthorized() {
        return authorized;
    }

    @Override
    public boolean init() {
        /* TODO: implement init() */
        return true;
    }

    @Override
    public List<AuthBackend> getAuthBackends() throws VaultConnectorException {
        try {
            String response = requestGet(PATH_AUTH, new HashMap<>());
            /* Parse response */
            AuthMethodsResponse amr = jsonMapper.readValue(response, AuthMethodsResponse.class);
            return amr.getSupportedMethods().stream().map(AuthMethod::getType).collect(Collectors.toList());
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public TokenResponse authToken(final String token) throws VaultConnectorException {
        /* set token */
        this.token = token;
        try {
            String response = requestPost(PATH_TOKEN_LOOKUP, new HashMap<>());
            TokenResponse res = jsonMapper.readValue(response, TokenResponse.class);
            authorized = true;
            return res;
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public AuthResponse authUserPass(final String username, final String password) throws VaultConnectorException {
        Map<String, String> payload = new HashMap<>();
        payload.put("password", password);
        try {
            /* Get response */
            String response = requestPost(PATH_AUTH_USERPASS + username, payload);
            /* Parse response */
            AuthResponse upr = jsonMapper.readValue(response, AuthResponse.class);
            /* verify response */
            this.token = upr.getAuth().getClientToken();
            this.authorized = true;
            return upr;
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException {
        Map<String, String> payload = new HashMap<>();
        payload.put("app_id", appID);
        payload.put("user_id", userID);
        try {
            /* Get response */
            String response = requestPost(PATH_AUTH_APPID + "login", payload);
            /* Parse response */
            AuthResponse auth = jsonMapper.readValue(response, AuthResponse.class);
            /* verify response */
            this.token = auth.getAuth().getClientToken();
            this.authorized = true;
            return auth;
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public boolean registerAppId(final String appID, final String policy, final String displayName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        Map<String, String> payload = new HashMap<>();
        payload.put("value", policy);
        payload.put("display_name", displayName);
        /* Get response */
        String response = requestPost(PATH_AUTH_APPID + "map/app-id/" + appID, payload);
        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");
        return true;
    }

    @Override
    public boolean registerUserId(final String appID, final String userID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        Map<String, String> payload = new HashMap<>();
        payload.put("value", appID);
        /* Get response */
        String response = requestPost(PATH_AUTH_APPID + "map/user-id/" + userID, payload);
        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");
        return true;
    }

    @Override
    public SecretResponse readSecret(final String key) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(PATH_SECRET + "/" + key, new HashMap<>());
            return jsonMapper.readValue(response, SecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public List<String> listSecrets(final String path) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        String response = requestGet(PATH_SECRET + "/" + path + "/?list=true", new HashMap<>());
        try {
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public boolean writeSecret(final String key, final String value) throws VaultConnectorException {
        if (key == null || key.isEmpty())
            throw new InvalidRequestException("Secret path must not be empty.");

        Map<String, String> param = new HashMap<>();
        param.put("value", value);
        return requestPost(PATH_SECRET + "/" + key, param).equals("");
    }



    /**
     * Execute HTTP request using POST method.
     * @param path      URL path (relative to base)
     * @param payload   Map of payload values (will be converted to JSON)
     * @return          HTTP response
     * @throws VaultConnectorException
     */
    private String requestPost(final String path, final Map payload) throws VaultConnectorException {
        /* Initialize post */
        HttpPost post = new HttpPost(baseURL + path);
        /* generate JSON from payload */
        StringEntity input;
        try {
            input = new StringEntity(jsonMapper.writeValueAsString(payload), HTTP.UTF_8);
        } catch (JsonProcessingException e) {
            throw new InvalidRequestException("Unable to parse response", e);
        }
        input.setContentEncoding("UTF-8");
        input.setContentType("application/json");
        post.setEntity(input);
        /* Set X-Vault-Token header */
        if (token != null)
            post.addHeader("X-Vault-Token", token);

        return request(post);
    }

    /**
     * Execute HTTP request using PUT method.
     * @param path      URL path (relative to base)
     * @param payload   Map of payload values (will be converted to JSON)
     * @return          HTTP response
     * @throws VaultConnectorException
     */
    private String requestPut(final String path, final Map<String, Object> payload) throws VaultConnectorException {
        /* Initialize post */
        HttpPut put = new HttpPut(baseURL + path);
        /* generate JSON from payload */
        StringEntity entity = null;
        try {
            entity = new StringEntity(jsonMapper.writeValueAsString(payload));
        } catch (UnsupportedEncodingException | JsonProcessingException e) {
            e.printStackTrace();
        }
        /* Parse parameters */
        put.setEntity(entity);
        /* Set X-Vault-Token header */
        if (token != null)
            put.addHeader("X-Vault-Token", token);

        return request(put);
    }

    /**
     * Execute HTTP request using GET method.
     * @param path      URL path (relative to base)
     * @param payload   Map of payload values (will be converted to JSON)
     * @return          HTTP response
     * @throws VaultConnectorException
     */
    private String requestGet(final String path, final Map<String, Object> payload) throws VaultConnectorException {
        /* Initialize post */
        HttpGet get = new HttpGet(baseURL + path);
        /* Parse parameters */
        HttpParams params = new BasicHttpParams();
        payload.forEach(params::setParameter);
        get.setParams(params);

        /* Set X-Vault-Token header */
        if (token != null)
            get.addHeader("X-Vault-Token", token);

        return request(get);
    }

    /**
     * Execute prepared HTTP request and return result
     * @param base      Prepares Request
     * @return          HTTP response
     * @throws VaultConnectorException
     */
    private String request(HttpRequestBase base) throws VaultConnectorException {
        /* Set JSON Header */
        base.addHeader("accept", "application/json");

        HttpResponse response = null;
        try {
            response = httpClient.execute(base);
            /* Check if response is valid */
            if (response == null)
                throw new InvalidResponseException("Response unavailable");
            switch (response.getStatusLine().getStatusCode()) {
                case 200:
                    return IOUtils.toString(response.getEntity().getContent());
                case 204:
                    return "";
                case 403:
                    throw new PermissionDeniedException();
                default:
                    InvalidResponseException ex = new InvalidResponseException("Invalid response code")
                            .withStatusCode(response.getStatusLine().getStatusCode());
                    try {
                        /* Try to parse error response */
                        ErrorResponse er = jsonMapper.readValue(IOUtils.toString(response.getEntity().getContent()),
                                ErrorResponse.class);
                        /* Check for "permission denied" response */
                        if (er.getErrors().size() > 0 && er.getErrors().get(0).equals("permission denied"))
                            throw new PermissionDeniedException();

                        throw ex.withResponse(er.toString());
                    }
                    catch (IOException e) {
                        throw ex;
                    }
            }
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to read response", e);
        }
        finally {
            if (response != null && response.getEntity() != null)
                try {
                    response.getEntity().consumeContent();
                } catch (IOException ignored) {
                }
        }
    }
}
