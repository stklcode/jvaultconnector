/*
 * Copyright 2016 Stefan Kalscheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.stklcode.jvault.connector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.*;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.*;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Vault Connector implementatin using Vault's HTTP API.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public class HTTPVaultConnector implements VaultConnector {
    private static final String PATH_PREFIX = "/v1/";
    private static final String PATH_SEAL_STATUS = "sys/seal-status";
    private static final String PATH_SEAL = "sys/seal";
    private static final String PATH_UNSEAL = "sys/unseal";
    private static final String PATH_INIT = "sys/init";
    private static final String PATH_RENEW = "sys/renew";
    private static final String PATH_AUTH = "sys/auth";
    private static final String PATH_TOKEN = "auth/token";
    private static final String PATH_LOOKUP = "/lookup";
    private static final String PATH_CREATE = "/create";
    private static final String PATH_CREATE_ORPHAN = "/create-orphan";
    private static final String PATH_AUTH_USERPASS = "auth/userpass/login/";
    private static final String PATH_AUTH_APPID = "auth/app-id/";
    private static final String PATH_AUTH_APPROLE = "auth/approle/";
    private static final String PATH_SECRET = "secret";
    private static final String PATH_REVOKE = "sys/revoke/";

    private final ObjectMapper jsonMapper;

    private final String baseURL;           /* Base URL of Vault */
    private final SSLContext sslContext;    /* Custom SSLSocketFactory */

    private boolean authorized = false;     /* authorization status */
    private String token;                   /* current token */
    private long tokenTTL = 0;              /* expiration time for current token */

    /**
     * Create connector using hostname and schema.
     *
     * @param hostname The hostname
     * @param useTLS   If TRUE, use HTTPS, otherwise HTTP
     */
    public HTTPVaultConnector(String hostname, boolean useTLS) {
        this(hostname, useTLS, null);
    }

    /**
     * Create connector using hostname, schema and port.
     *
     * @param hostname The hostname
     * @param useTLS   If TRUE, use HTTPS, otherwise HTTP
     * @param port     The port
     */
    public HTTPVaultConnector(String hostname, boolean useTLS, Integer port) {
        this(hostname, useTLS, port, PATH_PREFIX);
    }

    /**
     * Create connector using hostname, schema, port and path.
     *
     * @param hostname The hostname
     * @param useTLS   If TRUE, use HTTPS, otherwise HTTP
     * @param port     The port
     * @param prefix   HTTP API prefix (default: /v1/)
     */
    public HTTPVaultConnector(String hostname, boolean useTLS, Integer port, String prefix) {
        this(((useTLS) ? "https" : "http") +
                "://" + hostname +
                ((port != null) ? ":" + port : "") +
                prefix);
    }

    /**
     * Create connector using hostname, schema, port, path and trusted certificate.
     *
     * @param hostname   The hostname
     * @param useTLS     If TRUE, use HTTPS, otherwise HTTP
     * @param port       The port
     * @param prefix     HTTP API prefix (default: /v1/)
     * @param sslContext Custom SSL Context
     */
    public HTTPVaultConnector(String hostname, boolean useTLS, Integer port, String prefix, SSLContext sslContext) {
        this(((useTLS) ? "https" : "http") +
                        "://" + hostname +
                        ((port != null) ? ":" + port : "") +
                        prefix,
                sslContext);
    }

    /**
     * Create connector using full URL.
     *
     * @param baseURL The URL
     */
    public HTTPVaultConnector(String baseURL) {
        this(baseURL, null);
    }

    /**
     * Create connector using full URL and trusted certificate.
     *
     * @param baseURL The URL
     */
    public HTTPVaultConnector(String baseURL, SSLContext sslContext) {
        this.baseURL = baseURL;
        this.sslContext = sslContext;
        this.jsonMapper = new ObjectMapper();
    }

    @Override
    public void resetAuth() {
        token = null;
        tokenTTL = 0;
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
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
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
        Map<String, String> param = new HashMap<>();
        param.put("key", key);
        if (reset != null)
            param.put("reset", reset.toString());
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
        return authorized && (tokenTTL == 0 || tokenTTL >= System.currentTimeMillis());
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
            return amr.getSupportedMethods().values().stream().map(AuthMethod::getType).collect(Collectors.toList());
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
    }

    @Override
    public TokenResponse authToken(final String token) throws VaultConnectorException {
        /* set token */
        this.token = token;
        this.tokenTTL = 0;
        try {
            String response = requestPost(PATH_TOKEN + PATH_LOOKUP, new HashMap<>());
            TokenResponse res = jsonMapper.readValue(response, TokenResponse.class);
            authorized = true;
            return res;
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public AuthResponse authUserPass(final String username, final String password) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>();
        payload.put("password", password);
        return queryAuth(PATH_AUTH_USERPASS + username, payload);
    }

    @Override
    public AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>();
        payload.put("app_id", appID);
        payload.put("user_id", userID);
        return queryAuth(PATH_AUTH_APPID + "login", payload);
    }

    @Override
    public AuthResponse authAppRole(final String roleID, final String secretID) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>();
        payload.put("role_id", roleID);
        if (secretID != null)
            payload.put("secret_id", secretID);
        return queryAuth(PATH_AUTH_APPROLE + "login", payload);
    }

    /**
     * Query authorization request to given backend
     *
     * @param path    The path to request
     * @param payload Payload (credentials)
     * @return The AuthResponse
     * @throws VaultConnectorException on errors
     */
    private AuthResponse queryAuth(final String path, final Map<String, String> payload) throws VaultConnectorException {
        try {
            /* Get response */
            String response = requestPost(path, payload);
            /* Parse response */
            AuthResponse auth = jsonMapper.readValue(response, AuthResponse.class);
            /* verify response */
            this.token = auth.getAuth().getClientToken();
            this.tokenTTL = System.currentTimeMillis() + auth.getAuth().getLeaseDuration() * 1000L;
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
    public boolean createAppRole(final AppRole role) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Get response */
        String response = requestPost(PATH_AUTH_APPROLE + "role/" + role.getName(), role);
        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");

        /* Set custom ID if provided */
        return !(role.getId() != null && !role.getId().isEmpty()) || setAppRoleID(role.getName(), role.getId());
    }

    @Override
    public AppRoleResponse lookupAppRole(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(PATH_AUTH_APPROLE + "role/" + roleName, new HashMap<>());
            return jsonMapper.readValue(response, AppRoleResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
    }

    @Override
    public boolean deleteAppRole(String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestDelete(PATH_AUTH_APPROLE + "role/" + roleName);

        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");

        return true;
    }

    @Override
    public String getAppRoleID(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(PATH_AUTH_APPROLE + "role/" + roleName + "/role-id", new HashMap<>());
            return jsonMapper.readValue(response, RawDataResponse.class).getData().get("role_id").toString();
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
    }

    @Override
    public boolean setAppRoleID(final String roleName, final String roleID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        Map<String, String> payload = new HashMap<>();
        payload.put("role_id", roleID);
        String response = requestPost(PATH_AUTH_APPROLE + "role/" + roleName + "/role-id", payload);
        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");
        return true;
    }

    @Override
    public AppRoleSecretResponse createAppRoleSecret(final String roleName, final AppRoleSecret secret) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Get response */
        String response;
        if (secret.getId() != null && !secret.getId().isEmpty())
            response = requestPost(PATH_AUTH_APPROLE + "role/" + roleName + "/custom-secret-id", secret);
        else
            response = requestPost(PATH_AUTH_APPROLE + "role/" + roleName + "/secret-id", secret);

        try {
            /* Extract the secret ID from response */
            return jsonMapper.readValue(response, AppRoleSecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response.");
        }
    }

    @Override
    public AppRoleSecretResponse lookupAppRoleSecret(final String roleName, final String secretID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestPost(PATH_AUTH_APPROLE + "role/" + roleName + "/secret-id/lookup", new AppRoleSecret(secretID));
            return jsonMapper.readValue(response, AppRoleSecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public boolean destroyAppRoleSecret(final String roleName, final String secretID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestPost(PATH_AUTH_APPROLE + "role/" + roleName + "/secret-id/destroy", new AppRoleSecret(secretID));

        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");

        return true;
    }

    @Override
    public List<String> listAppRoles() throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        try {
            String response = requestGet(PATH_AUTH_APPROLE + "role?list=true", new HashMap<>());
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
    }

    @Override
    public List<String> listAppRoleSecretss(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        try {
            String response = requestGet(PATH_AUTH_APPROLE + "role/" + roleName + "/secret-id?list=true", new HashMap<>());
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
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
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
    }

    @Override
    public List<String> listSecrets(final String path) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        try {
            String response = requestGet(PATH_SECRET + "/" + path + "/?list=true", new HashMap<>());
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }
    }

    @Override
    public boolean writeSecret(final String key, final String value) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        if (key == null || key.isEmpty())
            throw new InvalidRequestException("Secret path must not be empty.");

        Map<String, String> param = new HashMap<>();
        param.put("value", value);
        return requestPost(PATH_SECRET + "/" + key, param).equals("");
    }

    @Override
    public boolean deleteSecret(String key) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestDelete(PATH_SECRET + "/" + key);

        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");

        return true;
    }

    @Override
    public boolean revoke(String leaseID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestPut(PATH_REVOKE + leaseID, new HashMap<>());

        /* Response should be code 204 without content */
        if (!response.equals(""))
            throw new InvalidResponseException("Received response where non was expected.");

        return true;
    }

    @Override
    public SecretResponse renew(String leaseID, Integer increment) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        Map<String, String> payload = new HashMap<>();
        payload.put("lease_id", leaseID);
        if (increment != null)
            payload.put("increment", increment.toString());

        /* Request HTTP response and parse Secret */
        try {
            String response = requestPut(PATH_RENEW, payload);
            return jsonMapper.readValue(response, SecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public AuthResponse createToken(final Token token) throws VaultConnectorException {
        return createTokenInternal(token, PATH_TOKEN + PATH_CREATE);
    }

    @Override
    public AuthResponse createToken(final Token token, boolean orphan) throws VaultConnectorException {
        return createTokenInternal(token, PATH_TOKEN + PATH_CREATE_ORPHAN);
    }

    @Override
    public AuthResponse createToken(final Token token, final String role) throws VaultConnectorException {
        if (role == null || role.isEmpty())
            throw new InvalidRequestException("No role name specified.");
        return createTokenInternal(token, PATH_TOKEN + PATH_CREATE + "/" + role);
    }

    /**
     * Create token.
     * Centralized method to handle different token creation requests.
     *
     * @param token the token
     * @param path  request path
     * @return the response
     * @throws VaultConnectorException on error
     */
    private AuthResponse createTokenInternal(final Token token, final String path) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        if (token == null)
            throw new InvalidRequestException("Token must be provided.");

        String response = requestPost(path, token);
        try {
            return jsonMapper.readValue(response, AuthResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        }
    }

    @Override
    public TokenResponse lookupToken(final String token) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(PATH_TOKEN + "/lookup/" + token, new HashMap<>());
            return jsonMapper.readValue(response, TokenResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to parse response", e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException("Invalid URI format.");
        }

    }


    /**
     * Execute HTTP request using POST method.
     *
     * @param path    URL path (relative to base)
     * @param payload Map of payload values (will be converted to JSON)
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String requestPost(final String path, final Object payload) throws VaultConnectorException {
        /* Initialize post */
        HttpPost post = new HttpPost(baseURL + path);
        /* generate JSON from payload */
        StringEntity input;
        try {
            input = new StringEntity(jsonMapper.writeValueAsString(payload), StandardCharsets.UTF_8);
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
     *
     * @param path    URL path (relative to base)
     * @param payload Map of payload values (will be converted to JSON)
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String requestPut(final String path, final Map<String, String> payload) throws VaultConnectorException {
        /* Initialize put */
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
     * Execute HTTP request using DELETE method.
     *
     * @param path URL path (relative to base)
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String requestDelete(final String path) throws VaultConnectorException {
        /* Initialize delete */
        HttpDelete delete = new HttpDelete(baseURL + path);
        /* Set X-Vault-Token header */
        if (token != null)
            delete.addHeader("X-Vault-Token", token);

        return request(delete);
    }

    /**
     * Execute HTTP request using GET method.
     *
     * @param path    URL path (relative to base)
     * @param payload Map of payload values (will be converted to JSON)
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String requestGet(final String path, final Map<String, String> payload) throws VaultConnectorException, URISyntaxException {
        /* Add parameters to URI */
        URIBuilder uriBuilder = new URIBuilder(baseURL + path);
        payload.forEach(uriBuilder::addParameter);

        /* Initialize request */
        HttpGet get = new HttpGet(uriBuilder.build());

        /* Set X-Vault-Token header */
        if (token != null)
            get.addHeader("X-Vault-Token", token);

        return request(get);
    }

    /**
     * Execute prepared HTTP request and return result.
     *
     * @param base Prepares Request
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String request(HttpRequestBase base) throws VaultConnectorException {
        /* Set JSON Header */
        base.addHeader("accept", "application/json");

        HttpResponse response = null;
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLContext(sslContext).build()) {
            response = httpClient.execute(base);
            /* Check if response is valid */
            if (response == null)
                throw new InvalidResponseException("Response unavailable");

            switch (response.getStatusLine().getStatusCode()) {
                case 200:
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()))) {
                        return br.lines().collect(Collectors.joining("\n"));
                    } catch (IOException ignored) {
                    }
                case 204:
                    return "";
                case 403:
                    throw new PermissionDeniedException();
                default:
                    InvalidResponseException ex = new InvalidResponseException("Invalid response code")
                            .withStatusCode(response.getStatusLine().getStatusCode());
                    if (response.getEntity() != null) {
                        try (BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()))) {
                            String responseString = br.lines().collect(Collectors.joining("\n"));
                            ErrorResponse er = jsonMapper.readValue(responseString, ErrorResponse.class);
                            /* Check for "permission denied" response */
                            if (er.getErrors().size() > 0 && er.getErrors().get(0).equals("permission denied"))
                                throw new PermissionDeniedException();
                            throw ex.withResponse(er.toString());
                        } catch (IOException ignored) {
                        }
                    }
                    throw ex;
            }
        } catch (IOException e) {
            throw new InvalidResponseException("Unable to read response", e);
        } finally {
            if (response != null && response.getEntity() != null)
                try {
                    EntityUtils.consume(response.getEntity());
                } catch (IOException ignored) {
                }
        }
    }
}
