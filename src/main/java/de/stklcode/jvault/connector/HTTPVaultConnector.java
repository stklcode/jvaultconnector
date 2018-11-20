/*
 * Copyright 2016-2018 Stefan Kalscheuer
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
import de.stklcode.jvault.connector.model.AppRole;
import de.stklcode.jvault.connector.model.AppRoleSecret;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.Token;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    private static final String PATH_RENEW = "sys/leases/renew";
    private static final String PATH_AUTH = "sys/auth";
    private static final String PATH_TOKEN = "auth/token";
    private static final String PATH_LOOKUP = "/lookup";
    private static final String PATH_CREATE = "/create";
    private static final String PATH_CREATE_ORPHAN = "/create-orphan";
    private static final String PATH_AUTH_USERPASS = "auth/userpass/login/";
    private static final String PATH_AUTH_APPID = "auth/app-id/";
    private static final String PATH_AUTH_APPROLE = "auth/approle/";
    private static final String PATH_AUTH_APPROLE_ROLE = "auth/approle/role/%s%s";
    private static final String PATH_REVOKE = "sys/leases/revoke/";
    private static final String PATH_HEALTH = "sys/health";

    private static final String HEADER_VAULT_TOKEN = "X-Vault-Token";

    public static final String DEFAULT_TLS_VERSION = "TLSv1.2";

    private final ObjectMapper jsonMapper;

    private final String baseURL;                   // Base URL of Vault.
    private final String tlsVersion;                // TLS version (#22).
    private final X509Certificate trustedCaCert;    // Trusted CA certificate.
    private final int retries;                      // Number of retries on 5xx errors.
    private final Integer timeout;                  // Timeout in milliseconds.

    private boolean authorized = false;             // Authorization status.
    private String token;                           // Current token.
    private long tokenTTL = 0;                      // Expiration time for current token.

    /**
     * Create connector using hostname and schema.
     *
     * @param hostname The hostname
     * @param useTLS   If TRUE, use HTTPS, otherwise HTTP
     */
    public HTTPVaultConnector(final String hostname, final boolean useTLS) {
        this(hostname, useTLS, null);
    }

    /**
     * Create connector using hostname, schema and port.
     *
     * @param hostname The hostname
     * @param useTLS   If TRUE, use HTTPS, otherwise HTTP
     * @param port     The port
     */
    public HTTPVaultConnector(final String hostname, final boolean useTLS, final Integer port) {
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
    public HTTPVaultConnector(final String hostname, final boolean useTLS, final Integer port, final String prefix) {
        this(((useTLS) ? "https" : "http")
                + "://" + hostname
                + ((port != null) ? ":" + port : "")
                + prefix);
    }

    /**
     * Create connector using hostname, schema, port, path and trusted certificate.
     *
     * @param hostname      The hostname
     * @param useTLS        If TRUE, use HTTPS, otherwise HTTP
     * @param port          The port
     * @param prefix        HTTP API prefix (default: /v1/)
     * @param trustedCaCert Trusted CA certificate
     */
    public HTTPVaultConnector(final String hostname,
                              final boolean useTLS,
                              final Integer port,
                              final String prefix,
                              final X509Certificate trustedCaCert) {
        this(hostname, useTLS, DEFAULT_TLS_VERSION, port, prefix, trustedCaCert, 0, null);
    }

    /**
     * Create connector using hostname, schema, port, path and trusted certificate.
     *
     * @param hostname        The hostname
     * @param useTLS          If TRUE, use HTTPS, otherwise HTTP
     * @param tlsVersion      TLS version
     * @param port            The port
     * @param prefix          HTTP API prefix (default: /v1/)
     * @param trustedCaCert   Trusted CA certificate
     * @param numberOfRetries Number of retries on 5xx errors
     * @param timeout         Timeout for HTTP requests (milliseconds)
     */
    public HTTPVaultConnector(final String hostname,
                              final boolean useTLS,
                              final String tlsVersion,
                              final Integer port,
                              final String prefix,
                              final X509Certificate trustedCaCert,
                              final int numberOfRetries,
                              final Integer timeout) {
        this(((useTLS) ? "https" : "http")
                        + "://" + hostname
                        + ((port != null) ? ":" + port : "")
                        + prefix,
                trustedCaCert,
                numberOfRetries,
                timeout,
                tlsVersion);
    }

    /**
     * Create connector using full URL.
     *
     * @param baseURL The URL
     */
    public HTTPVaultConnector(final String baseURL) {
        this(baseURL, null);
    }

    /**
     * Create connector using full URL and trusted certificate.
     *
     * @param baseURL       The URL
     * @param trustedCaCert Trusted CA certificate
     */
    public HTTPVaultConnector(final String baseURL, final X509Certificate trustedCaCert) {
        this(baseURL, trustedCaCert, 0, null);
    }

    /**
     * Create connector using full URL and trusted certificate.
     *
     * @param baseURL         The URL
     * @param trustedCaCert   Trusted CA certificate
     * @param numberOfRetries Number of retries on 5xx errors
     */
    public HTTPVaultConnector(final String baseURL, final X509Certificate trustedCaCert, final int numberOfRetries) {
        this(baseURL, trustedCaCert, numberOfRetries, null);
    }

    /**
     * Create connector using full URL and trusted certificate.
     *
     * @param baseURL         The URL
     * @param trustedCaCert   Trusted CA certificate
     * @param numberOfRetries Number of retries on 5xx errors
     * @param timeout         Timeout for HTTP requests (milliseconds)
     */
    public HTTPVaultConnector(final String baseURL,
                              final X509Certificate trustedCaCert,
                              final int numberOfRetries,
                              final Integer timeout) {
        this(baseURL, trustedCaCert, numberOfRetries, timeout, DEFAULT_TLS_VERSION);
    }

    /**
     * Create connector using full URL and trusted certificate.
     *
     * @param baseURL         The URL
     * @param trustedCaCert   Trusted CA certificate
     * @param numberOfRetries Number of retries on 5xx errors
     * @param timeout         Timeout for HTTP requests (milliseconds)
     * @param tlsVersion      TLS Version.
     */
    public HTTPVaultConnector(final String baseURL,
                              final X509Certificate trustedCaCert,
                              final int numberOfRetries,
                              final Integer timeout,
                              final String tlsVersion) {
        this.baseURL = baseURL;
        this.trustedCaCert = trustedCaCert;
        this.retries = numberOfRetries;
        this.timeout = timeout;
        this.tlsVersion = tlsVersion;
        this.jsonMapper = new ObjectMapper();
    }

    @Override
    public final void resetAuth() {
        token = null;
        tokenTTL = 0;
        authorized = false;
    }

    @Override
    public final SealResponse sealStatus() throws VaultConnectorException {
        try {
            String response = requestGet(PATH_SEAL_STATUS, new HashMap<>());
            return jsonMapper.readValue(response, SealResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final void seal() throws VaultConnectorException {
        requestPut(PATH_SEAL, new HashMap<>());
    }

    @Override
    public final SealResponse unseal(final String key, final Boolean reset) throws VaultConnectorException {
        Map<String, String> param = new HashMap<>();
        param.put("key", key);
        if (reset != null)
            param.put("reset", reset.toString());
        try {
            String response = requestPut(PATH_UNSEAL, param);
            return jsonMapper.readValue(response, SealResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    @Override
    public HealthResponse getHealth() throws VaultConnectorException {
        /* Force status code to be 200, so we don't need to modify the request sequence. */
        Map<String, String> param = new HashMap<>();
        param.put("standbycode", "200");    // Default: 429.
        param.put("sealedcode", "200");     // Default: 503.
        param.put("uninitcode", "200");     // Default: 501.
        try {
            String response = requestGet(PATH_HEALTH, param);
            /* Parse response */
            return jsonMapper.readValue(response, HealthResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException e) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final boolean isAuthorized() {
        return authorized && (tokenTTL == 0 || tokenTTL >= System.currentTimeMillis());
    }

    @Override
    public final List<AuthBackend> getAuthBackends() throws VaultConnectorException {
        try {
            String response = requestGet(PATH_AUTH, new HashMap<>());
            /* Parse response */
            AuthMethodsResponse amr = jsonMapper.readValue(response, AuthMethodsResponse.class);
            return amr.getSupportedMethods().values().stream().map(AuthMethod::getType).collect(Collectors.toList());
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final TokenResponse authToken(final String token) throws VaultConnectorException {
        /* set token */
        this.token = token;
        this.tokenTTL = 0;
        try {
            String response = requestPost(PATH_TOKEN + PATH_LOOKUP, new HashMap<>());
            TokenResponse res = jsonMapper.readValue(response, TokenResponse.class);
            authorized = true;
            return res;
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    @Override
    public final AuthResponse authUserPass(final String username, final String password)
            throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>();
        payload.put("password", password);
        return queryAuth(PATH_AUTH_USERPASS + username, payload);
    }

    @Override
    @Deprecated
    public final AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>();
        payload.put("app_id", appID);
        payload.put("user_id", userID);
        return queryAuth(PATH_AUTH_APPID + "login", payload);
    }

    @Override
    public final AuthResponse authAppRole(final String roleID, final String secretID) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>();
        payload.put("role_id", roleID);
        if (secretID != null)
            payload.put("secret_id", secretID);
        return queryAuth(PATH_AUTH_APPROLE + "login", payload);
    }

    /**
     * Query authorization request to given backend.
     *
     * @param path    The path to request
     * @param payload Payload (credentials)
     * @return The AuthResponse
     * @throws VaultConnectorException on errors
     */
    private AuthResponse queryAuth(final String path, final Map<String, String> payload)
            throws VaultConnectorException {
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
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    @Override
    @Deprecated
    public final boolean registerAppId(final String appID, final String policy, final String displayName)
            throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        Map<String, String> payload = new HashMap<>();
        payload.put("value", policy);
        payload.put("display_name", displayName);
        /* Get response */
        String response = requestPost(PATH_AUTH_APPID + "map/app-id/" + appID, payload);
        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        return true;
    }

    @Override
    @Deprecated
    public final boolean registerUserId(final String appID, final String userID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        Map<String, String> payload = new HashMap<>();
        payload.put("value", appID);
        /* Get response */
        String response = requestPost(PATH_AUTH_APPID + "map/user-id/" + userID, payload);
        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        return true;
    }

    @Override
    public final boolean createAppRole(final AppRole role) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Get response */
        String response = requestPost(String.format(PATH_AUTH_APPROLE_ROLE, role.getName(), ""), role);
        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);

        /* Set custom ID if provided */
        return !(role.getId() != null && !role.getId().isEmpty()) || setAppRoleID(role.getName(), role.getId());
    }

    @Override
    public final AppRoleResponse lookupAppRole(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(String.format(PATH_AUTH_APPROLE_ROLE, roleName, ""), new HashMap<>());
            return jsonMapper.readValue(response, AppRoleResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final boolean deleteAppRole(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestDelete(String.format(PATH_AUTH_APPROLE_ROLE, roleName, ""));

        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);

        return true;
    }

    @Override
    public final String getAppRoleID(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/role-id"), new HashMap<>());
            return jsonMapper.readValue(response, RawDataResponse.class).getData().get("role_id").toString();
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final boolean setAppRoleID(final String roleName, final String roleID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        Map<String, String> payload = new HashMap<>();
        payload.put("role_id", roleID);
        String response = requestPost(String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/role-id"), payload);
        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        return true;
    }

    @Override
    public final AppRoleSecretResponse createAppRoleSecret(final String roleName, final AppRoleSecret secret)
            throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Get response */
        String response;
        if (secret.getId() != null && !secret.getId().isEmpty())
            response = requestPost(String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/custom-secret-id"), secret);
        else
            response = requestPost(String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id"), secret);

        try {
            /* Extract the secret ID from response */
            return jsonMapper.readValue(response, AppRoleSecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE);
        }
    }

    @Override
    public final AppRoleSecretResponse lookupAppRoleSecret(final String roleName, final String secretID)
            throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestPost(
                    String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id/lookup"),
                    new AppRoleSecret(secretID));
            return jsonMapper.readValue(response, AppRoleSecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    @Override
    public final boolean destroyAppRoleSecret(final String roleName, final String secretID)
            throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestPost(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id/destroy"),
                new AppRoleSecret(secretID));

        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);

        return true;
    }

    @Override
    public final List<String> listAppRoles() throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        try {
            String response = requestGet(PATH_AUTH_APPROLE + "role?list=true", new HashMap<>());
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final List<String> listAppRoleSecrets(final String roleName) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        try {
            String response = requestGet(
                    String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id?list=true"),
                    new HashMap<>());
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final SecretResponse read(final String key) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(key, new HashMap<>());
            return jsonMapper.readValue(response, SecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final SecretResponse readSecretData(final String key) throws VaultConnectorException {
        if (!isAuthorized()) {
            throw new AuthorizationRequiredException();
        }
        /* Request HTTP response and parse secret metadata */
        try {
            String response = requestGet(PATH_SECRET + "data/" + key, new HashMap<>());
            return jsonMapper.readValue(response, SecretResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final MetadataResponse readSecretMetadata(final String key) throws VaultConnectorException {
        if (!isAuthorized()) {
            throw new AuthorizationRequiredException();
        }
        /* Request HTTP response and parse secret metadata */
        try {
            String response = requestGet(PATH_SECRET + "metadata/" + key, new HashMap<>());
            return jsonMapper.readValue(response, MetadataResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final List<String> list(final String path) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        try {
            String response = requestGet(path + "/?list=true", new HashMap<>());
            SecretListResponse secrets = jsonMapper.readValue(response, SecretListResponse.class);
            return secrets.getKeys();
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    @Override
    public final void write(final String key, final Map<String, Object> data, final Map<String, Object> options) throws VaultConnectorException {
        if (!isAuthorized()) {
            throw new AuthorizationRequiredException();
        }

        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("Secret path must not be empty.");
        }

        // By default data is directly passed as payload.
        Object payload = data;

        // If options are given, split payload in two parts.
        if (options != null) {
            Map<String, Object> payloadMap = new HashMap<>();
            payloadMap.put("data", data);
            payloadMap.put("options", options);
            payload = payloadMap;
        }

        if (!requestPost(key, payload).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    @Override
    public final void delete(final String key) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestDelete(key);

        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
    }

    @Override
    public final void revoke(final String leaseID) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();

        /* Request HTTP response and expect empty result */
        String response = requestPut(PATH_REVOKE + leaseID, new HashMap<>());

        /* Response should be code 204 without content */
        if (!response.isEmpty())
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
    }

    @Override
    public final SecretResponse renew(final String leaseID, final Integer increment) throws VaultConnectorException {
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
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    @Override
    public final AuthResponse createToken(final Token token) throws VaultConnectorException {
        return createTokenInternal(token, PATH_TOKEN + PATH_CREATE);
    }

    @Override
    public final AuthResponse createToken(final Token token, final boolean orphan) throws VaultConnectorException {
        return createTokenInternal(token, PATH_TOKEN + PATH_CREATE_ORPHAN);
    }

    @Override
    public final AuthResponse createToken(final Token token, final String role) throws VaultConnectorException {
        if (role == null || role.isEmpty())
            throw new InvalidRequestException("No role name specified.");
        return createTokenInternal(token, PATH_TOKEN + PATH_CREATE + "/" + role);
    }

    @Override
    public final void close() {
        authorized = false;
        token = null;
        tokenTTL = 0;
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
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    @Override
    public final TokenResponse lookupToken(final String token) throws VaultConnectorException {
        if (!isAuthorized())
            throw new AuthorizationRequiredException();
        /* Request HTTP response and parse Secret */
        try {
            String response = requestGet(PATH_TOKEN + "/lookup/" + token, new HashMap<>());
            return jsonMapper.readValue(response, TokenResponse.class);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        } catch (URISyntaxException ignored) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
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
            throw new InvalidRequestException(Error.PARSE_RESPONSE, e);
        }
        input.setContentEncoding("UTF-8");
        input.setContentType("application/json");
        post.setEntity(input);
        /* Set X-Vault-Token header */
        if (token != null)
            post.addHeader(HEADER_VAULT_TOKEN, token);

        return request(post, retries);
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
            throw new InvalidRequestException("Payload serialization failed", e);
        }
        /* Parse parameters */
        put.setEntity(entity);
        /* Set X-Vault-Token header */
        if (token != null)
            put.addHeader(HEADER_VAULT_TOKEN, token);

        return request(put, retries);
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
            delete.addHeader(HEADER_VAULT_TOKEN, token);

        return request(delete, retries);
    }

    /**
     * Execute HTTP request using GET method.
     *
     * @param path    URL path (relative to base)
     * @param payload Map of payload values (will be converted to JSON)
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @throws URISyntaxException      on invalid URI syntax
     */
    private String requestGet(final String path, final Map<String, String> payload)
            throws VaultConnectorException, URISyntaxException {
        /* Add parameters to URI */
        URIBuilder uriBuilder = new URIBuilder(baseURL + path);
        payload.forEach(uriBuilder::addParameter);

        /* Initialize request */
        HttpGet get = new HttpGet(uriBuilder.build());

        /* Set X-Vault-Token header */
        if (token != null)
            get.addHeader(HEADER_VAULT_TOKEN, token);

        return request(get, retries);
    }

    /**
     * Execute prepared HTTP request and return result.
     *
     * @param base    Prepares Request
     * @param retries number of retries
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String request(final HttpRequestBase base, final int retries) throws VaultConnectorException {
        /* Set JSON Header */
        base.addHeader("accept", "application/json");

        CloseableHttpResponse response = null;

        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(createSSLSocketFactory())
                .build()) {
            /* Set custom timeout, if defined */
            if (this.timeout != null)
                base.setConfig(RequestConfig.copy(RequestConfig.DEFAULT).setConnectTimeout(timeout).build());
            /* Execute request */
            response = httpClient.execute(base);
            /* Check if response is valid */
            if (response == null)
                throw new InvalidResponseException("Response unavailable");

            switch (response.getStatusLine().getStatusCode()) {
                case 200:
                    return handleResult(response);
                case 204:
                    return "";
                case 403:
                    throw new PermissionDeniedException();
                default:
                    if (response.getStatusLine().getStatusCode() >= 500
                            && response.getStatusLine().getStatusCode() < 600 && retries > 0) {
                        /* Retry on 5xx errors */
                        return request(base, retries - 1);
                    } else {
                        /* Fail on different error code and/or no retries left */
                        handleError(response);

                        /* Throw exception withoud details, if response entity is empty. */
                        throw new InvalidResponseException(Error.RESPONSE_CODE,
                                response.getStatusLine().getStatusCode());
                    }
            }
        } catch (IOException e) {
            throw new InvalidResponseException(Error.READ_RESPONSE, e);
        } finally {
            if (response != null && response.getEntity() != null)
                try {
                    EntityUtils.consume(response.getEntity());
                } catch (IOException ignored) {
                    // Exception ignored.
                }
        }
    }

    /**
     * Handle successful result.
     *
     * @param response The raw HTTP response (assuming status code 200)
     * @return Complete response body as String
     * @throws InvalidResponseException on reading errors
     */
    private String handleResult(final HttpResponse response) throws InvalidResponseException {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent()))) {
            return br.lines().collect(Collectors.joining("\n"));
        } catch (IOException ignored) {
            throw new InvalidResponseException(Error.READ_RESPONSE, 200);
        }
    }

    /**
     * Handle unsuccessful response. Throw detailed exception if possible.
     *
     * @param response The raw HTTP response (assuming status code 5xx)
     * @throws VaultConnectorException Expected exception with details to throw
     */
    private void handleError(final HttpResponse response) throws VaultConnectorException {
        if (response.getEntity() != null) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(response.getEntity().getContent()))) {
                String responseString = br.lines().collect(Collectors.joining("\n"));
                ErrorResponse er = jsonMapper.readValue(responseString, ErrorResponse.class);
                /* Check for "permission denied" response */
                if (!er.getErrors().isEmpty() && er.getErrors().get(0).equals("permission denied"))
                    throw new PermissionDeniedException();
                throw new InvalidResponseException(Error.RESPONSE_CODE,
                        response.getStatusLine().getStatusCode(), er.toString());
            } catch (IOException ignored) {
                // Exception ignored.
            }
        }
    }

    /**
     * Create a custom socket factory from trusted CA certificate.
     *
     * @return The factory.
     * @throws TlsException An error occured during initialization of the SSL context.
     * @since 0.8.0
     */
    private SSLConnectionSocketFactory createSSLSocketFactory() throws TlsException {
        try {
            // Create Keystore with trusted certificate.
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("trustedCert", trustedCaCert);

            // Initialize TrustManager.
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // Create context usint this TrustManager.
            SSLContext context = SSLContext.getInstance(tlsVersion);
            context.init(null, tmf.getTrustManagers(), new SecureRandom());

            return new SSLConnectionSocketFactory(
                    context,
                    null,
                    null,
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e) {
            throw new TlsException(Error.INIT_SSL_CONTEXT, e);
        }
    }

    /**
     * Inner class to bundle common error messages.
     */
    private static final class Error {
        private static final String READ_RESPONSE = "Unable to read response";
        private static final String PARSE_RESPONSE = "Unable to parse response";
        private static final String UNEXPECTED_RESPONSE = "Received response where none was expected";
        private static final String URI_FORMAT = "Invalid URI format";
        private static final String RESPONSE_CODE = "Invalid response code";
        private static final String INIT_SSL_CONTEXT = "Unable to intialize SSLContext";

        /**
         * Constructor hidden, this class should not be instantiated.
         */
        private Error() {
        }
    }
}
