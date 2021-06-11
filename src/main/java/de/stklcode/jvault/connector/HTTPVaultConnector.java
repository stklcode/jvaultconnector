/*
 * Copyright 2016-2021 Stefan Kalscheuer
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

import de.stklcode.jvault.connector.exception.AuthorizationRequiredException;
import de.stklcode.jvault.connector.exception.InvalidRequestException;
import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.internal.RequestHelper;
import de.stklcode.jvault.connector.model.*;
import de.stklcode.jvault.connector.model.response.*;
import de.stklcode.jvault.connector.model.response.embedded.AuthMethod;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;

/**
 * Vault Connector implementation using Vault's HTTP API.
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
    private static final String PATH_ROLES = "/roles";
    private static final String PATH_CREATE_ORPHAN = "/create-orphan";
    private static final String PATH_AUTH_USERPASS = "auth/userpass/login/";
    private static final String PATH_AUTH_APPID = "auth/app-id/";
    private static final String PATH_AUTH_APPROLE = "auth/approle/";
    private static final String PATH_AUTH_APPROLE_ROLE = "auth/approle/role/%s%s";
    private static final String PATH_REVOKE = "sys/leases/revoke/";
    private static final String PATH_HEALTH = "sys/health";
    private static final String PATH_DATA = "/data/";
    private static final String PATH_METADATA = "/metadata/";
    private static final String PATH_DELETE = "/delete/";
    private static final String PATH_UNDELETE = "/undelete/";
    private static final String PATH_DESTROY = "/destroy/";

    public static final String DEFAULT_TLS_VERSION = "TLSv1.2";

    private final RequestHelper request;

    private boolean authorized = false;     // Authorization status.
    private String token;                   // Current token.
    private long tokenTTL = 0;              // Expiration time for current token.

    /**
     * Get a new builder for a connector.
     *
     * @return Builder instance.
     * @since 0.9.5
     */
    public static HTTPVaultConnectorBuilder builder() {
        return new HTTPVaultConnectorBuilder();
    }

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
        this.request = new RequestHelper(baseURL, numberOfRetries, timeout, tlsVersion, trustedCaCert);
    }

    @Override
    public final void resetAuth() {
        token = null;
        tokenTTL = 0;
        authorized = false;
    }

    @Override
    public final SealResponse sealStatus() throws VaultConnectorException {
        return request.get(PATH_SEAL_STATUS, emptyMap(), token, SealResponse.class);
    }

    @Override
    public final void seal() throws VaultConnectorException {
        request.put(PATH_SEAL, emptyMap(), token);
    }

    @Override
    public final SealResponse unseal(final String key, final Boolean reset) throws VaultConnectorException {
        Map<String, String> param = new HashMap<>(2, 1);
        param.put("key", key);
        if (reset != null) {
            param.put("reset", reset.toString());
        }

        return request.put(PATH_UNSEAL, param, token, SealResponse.class);
    }

    @Override
    public HealthResponse getHealth() throws VaultConnectorException {
        /* Force status code to be 200, so we don't need to modify the request sequence. */
        Map<String, String> param = new HashMap<>(3, 1);
        param.put("standbycode", "200");    // Default: 429.
        param.put("sealedcode", "200");     // Default: 503.
        param.put("uninitcode", "200");     // Default: 501.

        return request.get(PATH_HEALTH, param, token, HealthResponse.class);
    }

    @Override
    public final boolean isAuthorized() {
        return authorized && (tokenTTL == 0 || tokenTTL >= System.currentTimeMillis());
    }

    @Override
    public final List<AuthBackend> getAuthBackends() throws VaultConnectorException {
        /* Issue request and parse response */
        AuthMethodsResponse amr = request.get(PATH_AUTH, emptyMap(), token, AuthMethodsResponse.class);

        return amr.getSupportedMethods().values().stream().map(AuthMethod::getType).collect(Collectors.toList());
    }

    @Override
    public final TokenResponse authToken(final String token) throws VaultConnectorException {
        /* set token */
        this.token = token;
        this.tokenTTL = 0;
        TokenResponse res = request.post(PATH_TOKEN + PATH_LOOKUP, emptyMap(), token, TokenResponse.class);
        authorized = true;

        return res;
    }

    @Override
    public final AuthResponse authUserPass(final String username, final String password)
            throws VaultConnectorException {
        final Map<String, String> payload = singletonMap("password", password);
        return queryAuth(PATH_AUTH_USERPASS + username, payload);
    }

    @Override
    @Deprecated
    public final AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>(2, 1);
        payload.put("app_id", appID);
        payload.put("user_id", userID);
        return queryAuth(PATH_AUTH_APPID + "login", payload);
    }

    @Override
    public final AuthResponse authAppRole(final String roleID, final String secretID) throws VaultConnectorException {
        final Map<String, String> payload = new HashMap<>(2, 1);
        payload.put("role_id", roleID);
        if (secretID != null) {
            payload.put("secret_id", secretID);
        }
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
        /* Issue request and parse response */
        AuthResponse auth = request.post(path, payload, token, AuthResponse.class);
        /* verify response */
        this.token = auth.getAuth().getClientToken();
        this.tokenTTL = System.currentTimeMillis() + auth.getAuth().getLeaseDuration() * 1000L;
        this.authorized = true;

        return auth;
    }

    @Override
    @Deprecated
    public final boolean registerAppId(final String appID, final String policy, final String displayName)
            throws VaultConnectorException {
        requireAuth();
        Map<String, String> payload = new HashMap<>(2, 1);
        payload.put("value", policy);
        payload.put("display_name", displayName);

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(PATH_AUTH_APPID + "map/app-id/" + appID, payload, token);

        return true;
    }

    @Override
    @Deprecated
    public final boolean registerUserId(final String appID, final String userID) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(
                PATH_AUTH_APPID + "map/user-id/" + userID,
                singletonMap("value", appID),
                token
        );

        return true;
    }

    @Override
    public final boolean createAppRole(final AppRole role) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(String.format(PATH_AUTH_APPROLE_ROLE, role.getName(), ""), role, token);

        /* Set custom ID if provided */
        return !(role.getId() != null && !role.getId().isEmpty()) || setAppRoleID(role.getName(), role.getId());
    }

    @Override
    public final AppRoleResponse lookupAppRole(final String roleName) throws VaultConnectorException {
        requireAuth();
        /* Request HTTP response and parse Secret */
        return request.get(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, ""),
                emptyMap(),
                token,
                AppRoleResponse.class
        );
    }

    @Override
    public final boolean deleteAppRole(final String roleName) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.deleteWithoutResponse(String.format(PATH_AUTH_APPROLE_ROLE, roleName, ""), token);

        return true;
    }

    @Override
    public final String getAppRoleID(final String roleName) throws VaultConnectorException {
        requireAuth();
        /* Issue request, parse response and extract Role ID */
        return request.get(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/role-id"),
                emptyMap(),
                token,
                RawDataResponse.class
        ).getData().get("role_id").toString();
    }

    @Override
    public final boolean setAppRoleID(final String roleName, final String roleID) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/role-id"),
                singletonMap("role_id", roleID),
                token
        );

        return true;
    }

    @Override
    public final AppRoleSecretResponse createAppRoleSecret(final String roleName, final AppRoleSecret secret)
            throws VaultConnectorException {
        requireAuth();

        if (secret.getId() != null && !secret.getId().isEmpty()) {
            return request.post(
                    String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/custom-secret-id"),
                    secret,
                    token,
                    AppRoleSecretResponse.class
            );
        } else {
            return request.post(
                    String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id"),
                    secret, token,
                    AppRoleSecretResponse.class
            );
        }
    }

    @Override
    public final AppRoleSecretResponse lookupAppRoleSecret(final String roleName, final String secretID)
            throws VaultConnectorException {
        requireAuth();

        /* Issue request and parse secret response */
        return request.post(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id/lookup"),
                new AppRoleSecret(secretID),
                token,
                AppRoleSecretResponse.class
        );
    }

    @Override
    public final boolean destroyAppRoleSecret(final String roleName, final String secretID)
            throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id/destroy"),
                new AppRoleSecret(secretID),
                token);

        return true;
    }

    @Override
    public final List<String> listAppRoles() throws VaultConnectorException {
        requireAuth();

        SecretListResponse secrets = request.get(
                PATH_AUTH_APPROLE + "role?list=true",
                emptyMap(),
                token,
                SecretListResponse.class
        );

        return secrets.getKeys();
    }

    @Override
    public final List<String> listAppRoleSecrets(final String roleName) throws VaultConnectorException {
        requireAuth();

        SecretListResponse secrets = request.get(
                String.format(PATH_AUTH_APPROLE_ROLE, roleName, "/secret-id?list=true"),
                emptyMap(),
                token,
                SecretListResponse.class
        );

        return secrets.getKeys();
    }

    @Override
    public final SecretResponse read(final String key) throws VaultConnectorException {
        requireAuth();
        /* Issue request and parse secret response */
        return request.get(key, emptyMap(), token, SecretResponse.class);
    }

    @Override
    public final SecretResponse readSecretVersion(final String mount, final String key, final Integer version) throws VaultConnectorException {
        requireAuth();
        /* Request HTTP response and parse secret metadata */
        Map<String, String> args = new HashMap<>(1, 1);
        if (version != null) {
            args.put("version", version.toString());
        }

        return request.get(mount + PATH_DATA + key, args, token, SecretResponse.class);
    }

    @Override
    public final MetadataResponse readSecretMetadata(final String mount, final String key) throws VaultConnectorException {
        requireAuth();

        /* Request HTTP response and parse secret metadata */
        return request.get(mount + PATH_METADATA + key, emptyMap(), token, MetadataResponse.class);
    }

    @Override
    public void updateSecretMetadata(final String mount, final String key, final Integer maxVersions, final boolean casRequired) throws VaultConnectorException {
        requireAuth();

        Map<String, Object> payload = new HashMap<>(2, 1);
        if (maxVersions != null) {
            payload.put("max_versions", maxVersions);
        }
        payload.put("cas_required", casRequired);

        write(mount + PATH_METADATA + key, payload);
    }

    @Override
    public final SecretVersionResponse writeSecretData(final String mount, final String key, final Map<String, Object> data, final Integer cas) throws VaultConnectorException {
        requireAuth();

        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("Secret path must not be empty.");
        }

        // Add CAS value to options map if present.
        Map<String, Object> options = new HashMap<>(1, 1);
        if (cas != null) {
            options.put("cas", cas);
        }

        Map<String, Object> payload = new HashMap<>(2, 1);
        payload.put("data", data);
        payload.put("options", options);

        /* Issue request and parse metadata response */
        return request.post(mount + PATH_DATA + key, payload, token, SecretVersionResponse.class);
    }

    @Override
    public final List<String> list(final String path) throws VaultConnectorException {
        requireAuth();

        SecretListResponse secrets = request.get(path + "/?list=true", emptyMap(), token, SecretListResponse.class);

        return secrets.getKeys();
    }

    @Override
    public final void write(final String key, final Map<String, Object> data, final Map<String, Object> options) throws VaultConnectorException {
        requireAuth();

        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("Secret path must not be empty.");
        }

        // By default data is directly passed as payload.
        Object payload = data;

        // If options are given, split payload in two parts.
        if (options != null) {
            Map<String, Object> payloadMap = new HashMap<>(2, 1);
            payloadMap.put("data", data);
            payloadMap.put("options", options);
            payload = payloadMap;
        }

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(key, payload, token);
    }

    @Override
    public final void delete(final String key) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.deleteWithoutResponse(key, token);
    }

    @Override
    public final void deleteLatestSecretVersion(final String mount, final String key) throws VaultConnectorException {
        delete(mount + PATH_DATA + key);
    }

    @Override
    public final void deleteAllSecretVersions(final String mount, final String key) throws VaultConnectorException {
        delete(mount + PATH_METADATA + key);
    }

    @Override
    public final void deleteSecretVersions(final String mount, final String key, final int... versions) throws VaultConnectorException {
        handleSecretVersions(mount, PATH_DELETE, key, versions);
    }

    @Override
    public final void undeleteSecretVersions(final String mount, final String key, final int... versions) throws VaultConnectorException {
        handleSecretVersions(mount, PATH_UNDELETE, key, versions);
    }

    @Override
    public final void destroySecretVersions(final String mount, final String key, final int... versions) throws VaultConnectorException {
        handleSecretVersions(mount, PATH_DESTROY, key, versions);
    }

    /**
     * Common method to bundle secret version operations.
     *
     * @param mount    Secret store mount point (without leading or trailing slash).
     * @param pathPart Path part to query.
     * @param key      Secret key.
     * @param versions Versions to handle.
     * @throws VaultConnectorException on error
     * @since 0.8
     */
    private void handleSecretVersions(final String mount, final String pathPart, final String key, final int... versions) throws VaultConnectorException {
        requireAuth();

        /* Request HTTP response and expect empty result */
        Map<String, Object> payload = singletonMap("versions", versions);

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(mount + pathPart + key, payload, token);
    }

    @Override
    public final void revoke(final String leaseID) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.putWithoutResponse(PATH_REVOKE + leaseID, emptyMap(), token);
    }

    @Override
    public final SecretResponse renew(final String leaseID, final Integer increment) throws VaultConnectorException {
        requireAuth();

        Map<String, String> payload = new HashMap<>(2, 1);
        payload.put("lease_id", leaseID);
        if (increment != null) {
            payload.put("increment", increment.toString());
        }

        /* Issue request and parse secret response */
        return request.put(PATH_RENEW, payload, token, SecretResponse.class);
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
        if (role == null || role.isEmpty()) {
            throw new InvalidRequestException("No role name specified.");
        }
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
        requireAuth();

        if (token == null) {
            throw new InvalidRequestException("Token must be provided.");
        }

        return request.post(path, token, this.token, AuthResponse.class);
    }

    @Override
    public final TokenResponse lookupToken(final String token) throws VaultConnectorException {
        requireAuth();

        /* Request HTTP response and parse Secret */
        return request.get(
                PATH_TOKEN + PATH_LOOKUP,
                singletonMap("token", token),
                token,
                TokenResponse.class
        );
    }

    @Override
    public boolean createOrUpdateTokenRole(final String name, final TokenRole role) throws VaultConnectorException {
        requireAuth();

        if (name == null) {
            throw new InvalidRequestException("Role name must be provided.");
        } else if (role == null) {
            throw new InvalidRequestException("Role must be provided.");
        }

        // Issue request and expect code 204 with empty response.
        request.postWithoutResponse(PATH_TOKEN + PATH_ROLES + "/" + name, role, token);

        return true;
    }

    @Override
    public TokenRoleResponse readTokenRole(final String name) throws VaultConnectorException {
        requireAuth();

        // Request HTTP response and parse response.
        return request.get(PATH_TOKEN + PATH_ROLES + "/" + name, emptyMap(), token, TokenRoleResponse.class);
    }

    @Override
    public List<String> listTokenRoles() throws VaultConnectorException {
        requireAuth();

        return list(PATH_TOKEN + PATH_ROLES);
    }

    @Override
    public boolean deleteTokenRole(final String name) throws VaultConnectorException {
        requireAuth();

        if (name == null) {
            throw new InvalidRequestException("Role name must be provided.");
        }

        // Issue request and expect code 204 with empty response.
        request.deleteWithoutResponse(PATH_TOKEN + PATH_ROLES + "/" + name, token);

        return true;
    }

    /**
     * Check for required authorization.
     *
     * @throws AuthorizationRequiredException Connector is not authorized.
     * @since 0.8 Bundled in method to reduce repetition.
     */
    private void requireAuth() throws AuthorizationRequiredException {
        if (!isAuthorized()) {
            throw new AuthorizationRequiredException();
        }
    }
}
