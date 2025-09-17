/*
 * Copyright 2016-2025 Stefan Kalscheuer
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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static de.stklcode.jvault.connector.internal.RequestHelper.encode;
import static de.stklcode.jvault.connector.internal.VaultApiPath.*;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;

/**
 * Vault Connector implementation using Vault's HTTP API.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 */
public class HTTPVaultConnector implements VaultConnector {
    private final RequestHelper request;

    private boolean authorized = false;     // Authorization status.
    private String token;                   // Current token.
    private long tokenTTL = 0;              // Expiration time for current token.

    /**
     * Create connector using a {@link HTTPVaultConnectorBuilder}.
     *
     * @param builder The builder.
     */
    HTTPVaultConnector(final HTTPVaultConnectorBuilder builder) {
        this.request = new RequestHelper(
            ((builder.isWithTLS()) ? "https" : "http") + "://" +
                builder.getHost() +
                ((builder.getPort() != null) ? ":" + builder.getPort() : "") +
                builder.getPrefix(),
            builder.getNumberOfRetries(),
            builder.getTimeout(),
            builder.getTlsVersion(),
            builder.getTrustedCA()
        );
    }

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
     * Get a new builder for a connector.
     *
     * @param baseURL Base URL.
     * @return Builder instance.
     * @throws URISyntaxException Invalid URI syntax.
     * @since 1.0
     */
    public static HTTPVaultConnectorBuilder builder(String baseURL) throws URISyntaxException {
        return new HTTPVaultConnectorBuilder().withBaseURL(baseURL);
    }

    /**
     * Get a new builder for a connector.
     *
     * @param baseURL Base URL.
     * @return Builder instance.
     * @since 1.0
     */
    public static HTTPVaultConnectorBuilder builder(URI baseURL) {
        return new HTTPVaultConnectorBuilder().withBaseURL(baseURL);
    }

    @Override
    public final void resetAuth() {
        token = null;
        tokenTTL = 0;
        authorized = false;
    }

    @Override
    public final SealResponse sealStatus() throws VaultConnectorException {
        return request.get(SYS_SEAL_STATUS, emptyMap(), token, SealResponse.class);
    }

    @Override
    public final void seal() throws VaultConnectorException {
        request.put(SYS_SEAL, emptyMap(), token);
    }

    @Override
    public final SealResponse unseal(final String key, final Boolean reset) throws VaultConnectorException {
        Map<String, String> param = mapOfStrings(
            "key", key,
            "reset", reset
        );

        return request.put(SYS_UNSEAL, param, token, SealResponse.class);
    }

    @Override
    public HealthResponse getHealth() throws VaultConnectorException {

        return request.get(
            SYS_HEALTH,
            // Force status code to be 200, so we don't need to modify the request sequence.
            Map.of(
                "standbycode", "200",   // Default: 429.
                "sealedcode", "200",    // Default: 503.
                "uninitcode", "200"     // Default: 501.
            ),
            token,
            HealthResponse.class
        );
    }

    @Override
    public final boolean isAuthorized() {
        return authorized && (tokenTTL == 0 || tokenTTL >= System.currentTimeMillis());
    }

    @Override
    public final List<AuthBackend> getAuthBackends() throws VaultConnectorException {
        /* Issue request and parse response */
        AuthMethodsResponse amr = request.get(SYS_AUTH, emptyMap(), token, AuthMethodsResponse.class);

        return amr.getSupportedMethods().values().stream().map(AuthMethod::getType).toList();
    }

    @Override
    public final TokenResponse authToken(final String token) throws VaultConnectorException {
        /* set token */
        this.token = token;
        this.tokenTTL = 0;
        TokenResponse res = request.get(AUTH_TOKEN + TOKEN_LOOKUP_SELF, emptyMap(), token, TokenResponse.class);
        authorized = true;

        return res;
    }

    @Override
    public final AuthResponse authUserPass(final String username, final String password)
        throws VaultConnectorException {
        final Map<String, String> payload = singletonMap("password", password);
        return queryAuth(AUTH_USERPASS_LOGIN + encode(username), payload);
    }

    @Override
    public final AuthResponse authAppRole(final String roleID, final String secretID) throws VaultConnectorException {
        final Map<String, String> payload = mapOfStrings(
            "role_id", roleID,
            "secret_id", secretID
        );
        return queryAuth(AUTH_APPROLE + "login", payload);
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
    public final boolean createAppRole(final AppRole role) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.postWithoutResponse(AUTH_APPROLE_ROLE + encode(role.getName()), role, token);

        /* Set custom ID if provided */
        return !(role.getId() != null && !role.getId().isEmpty()) || setAppRoleID(role.getName(), role.getId());
    }

    @Override
    public final AppRoleResponse lookupAppRole(final String roleName) throws VaultConnectorException {
        requireAuth();
        /* Request HTTP response and parse Secret */
        return request.get(
            AUTH_APPROLE_ROLE + encode(roleName),
            emptyMap(),
            token,
            AppRoleResponse.class
        );
    }

    @Override
    public final boolean deleteAppRole(final String roleName) throws VaultConnectorException {
        requireAuth();

        /* Issue request and expect code 204 with empty response */
        request.deleteWithoutResponse(AUTH_APPROLE_ROLE + encode(roleName), token);

        return true;
    }

    @Override
    public final String getAppRoleID(final String roleName) throws VaultConnectorException {
        requireAuth();
        /* Issue request, parse response and extract Role ID */
        return request.get(
            AUTH_APPROLE_ROLE + encode(roleName) + "/role-id",
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
            AUTH_APPROLE_ROLE + encode(roleName) + "/role-id",
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
                AUTH_APPROLE_ROLE + encode(roleName) + "/custom-secret-id",
                secret,
                token,
                AppRoleSecretResponse.class
            );
        } else {
            return request.post(
                AUTH_APPROLE_ROLE + encode(roleName) + "/secret-id",
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
            AUTH_APPROLE_ROLE + encode(roleName) + "/secret-id/lookup",
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
            AUTH_APPROLE_ROLE + encode(roleName) + "/secret-id/destroy",
            new AppRoleSecret(secretID),
            token);

        return true;
    }

    @Override
    public final List<String> listAppRoles() throws VaultConnectorException {
        requireAuth();

        SecretListResponse secrets = request.get(
            AUTH_APPROLE + "role?list=true",
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
            AUTH_APPROLE_ROLE + encode(roleName) + "/secret-id?list=true",
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
        return request.get(key, emptyMap(), token, PlainSecretResponse.class);
    }

    @Override
    public final SecretResponse readSecretVersion(final String mount, final String key, final Integer version)
        throws VaultConnectorException {
        requireAuth();
        /* Request HTTP response and parse secret metadata */
        Map<String, String> args = mapOfStrings("version", version);

        return request.get(mount + SECRET_DATA + key, args, token, MetaSecretResponse.class);
    }

    @Override
    public final MetadataResponse readSecretMetadata(final String mount, final String key)
        throws VaultConnectorException {
        requireAuth();

        /* Request HTTP response and parse secret metadata */
        return request.get(mount + SECRET_METADATA + key, emptyMap(), token, MetadataResponse.class);
    }

    @Override
    public void updateSecretMetadata(final String mount,
                                     final String key,
                                     final Integer maxVersions,
                                     final boolean casRequired) throws VaultConnectorException {
        requireAuth();

        Map<String, Object> payload = mapOf(
            "max_versions", maxVersions,
            "cas_required", casRequired
        );

        write(mount + SECRET_METADATA + key, payload);
    }

    @Override
    public final SecretVersionResponse writeSecretData(final String mount,
                                                       final String key,
                                                       final Map<String, Object> data,
                                                       final Integer cas) throws VaultConnectorException {
        requireAuth();

        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("Secret path must not be empty.");
        }

        // Add CAS value to options map if present.
        Map<String, Object> options = mapOf("cas", cas);

        /* Issue request and parse metadata response */
        return request.post(
            mount + SECRET_DATA + key,
            Map.of(
                "data", data,
                "options", options
            ),
            token,
            SecretVersionResponse.class
        );
    }

    @Override
    public final List<String> list(final String path) throws VaultConnectorException {
        requireAuth();

        SecretListResponse secrets = request.get(path + "/?list=true", emptyMap(), token, SecretListResponse.class);

        return secrets.getKeys();
    }

    @Override
    public final void write(final String key, final Map<String, Object> data, final Map<String, Object> options)
        throws VaultConnectorException {
        requireAuth();

        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("Secret path must not be empty.");
        }

        // By default, data is directly passed as payload.
        Object payload = data;

        // If options are given, split payload in two parts.
        if (options != null) {
            payload = Map.of(
                "data", data,
                "options", options
            );
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
        delete(mount + SECRET_DATA + key);
    }

    @Override
    public final void deleteAllSecretVersions(final String mount, final String key) throws VaultConnectorException {
        delete(mount + SECRET_METADATA + key);
    }

    @Override
    public final void deleteSecretVersions(final String mount, final String key, final int... versions)
        throws VaultConnectorException {
        handleSecretVersions(mount, SECRET_DELETE, key, versions);
    }

    @Override
    public final void undeleteSecretVersions(final String mount, final String key, final int... versions)
        throws VaultConnectorException {
        handleSecretVersions(mount, SECRET_UNDELETE, key, versions);
    }

    @Override
    public final void destroySecretVersions(final String mount, final String key, final int... versions)
        throws VaultConnectorException {
        handleSecretVersions(mount, SECRET_DESTROY, key, versions);
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
    private void handleSecretVersions(final String mount,
                                      final String pathPart,
                                      final String key,
                                      final int... versions) throws VaultConnectorException {
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
        request.putWithoutResponse(SYS_LEASES_REVOKE + encode(leaseID), emptyMap(), token);
    }

    @Override
    public final SecretResponse renew(final String leaseID, final Integer increment) throws VaultConnectorException {
        requireAuth();

        Map<String, String> payload = mapOfStrings(
            "lease_id", leaseID,
            "increment", increment
        );

        /* Issue request and parse secret response */
        return request.put(SYS_LEASES_RENEW, payload, token, SecretResponse.class);
    }

    @Override
    public final AuthResponse createToken(final Token token) throws VaultConnectorException {
        return createTokenInternal(token, AUTH_TOKEN + TOKEN_CREATE);
    }

    @Override
    public final AuthResponse createToken(final Token token, final boolean orphan) throws VaultConnectorException {
        return createTokenInternal(token, AUTH_TOKEN + TOKEN_CREATE_ORPHAN);
    }

    @Override
    public final AuthResponse createToken(final Token token, final String role) throws VaultConnectorException {
        if (role == null || role.isEmpty()) {
            throw new InvalidRequestException("No role name specified.");
        }
        return createTokenInternal(token, AUTH_TOKEN + TOKEN_CREATE + "/" + encode(role));
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
            AUTH_TOKEN + TOKEN_LOOKUP,
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
        request.postWithoutResponse(AUTH_TOKEN + TOKEN_ROLES + "/" + encode(name), role, token);

        return true;
    }

    @Override
    public TokenRoleResponse readTokenRole(final String name) throws VaultConnectorException {
        requireAuth();

        // Request HTTP response and parse response.
        return request.get(AUTH_TOKEN + TOKEN_ROLES + "/" + encode(name), emptyMap(), token, TokenRoleResponse.class);
    }

    @Override
    public List<String> listTokenRoles() throws VaultConnectorException {
        requireAuth();

        return list(AUTH_TOKEN + TOKEN_ROLES);
    }

    @Override
    public boolean deleteTokenRole(final String name) throws VaultConnectorException {
        requireAuth();

        if (name == null) {
            throw new InvalidRequestException("Role name must be provided.");
        }

        // Issue request and expect code 204 with empty response.
        request.deleteWithoutResponse(AUTH_TOKEN + TOKEN_ROLES + "/" + encode(name), token);

        return true;
    }

    @Override
    public final TransitResponse transitEncrypt(final String keyName, final String plaintext)
        throws VaultConnectorException {
        requireAuth();

        Map<String, Object> payload = mapOf(
            "plaintext", plaintext
        );

        return request.post(TRANSIT_ENCRYPT + encode(keyName), payload, token, TransitResponse.class);
    }

    @Override
    public final TransitResponse transitDecrypt(final String keyName, final String ciphertext)
        throws VaultConnectorException {
        requireAuth();

        Map<String, Object> payload = mapOf(
            "ciphertext", ciphertext
        );

        return request.post(TRANSIT_DECRYPT + encode(keyName), payload, token, TransitResponse.class);
    }

    @Override
    public final TransitResponse transitHash(final String algorithm, final String input, final String format)
        throws VaultConnectorException {
        if (format != null && !"hex".equals(format) && !"base64".equals(format)) {
            throw new IllegalArgumentException("Unsupported format " + format);
        }

        requireAuth();

        Map<String, Object> payload = mapOf(
            "input", input,
            "format", format
        );

        return request.post(TRANSIT_HASH + encode(algorithm), payload, token, TransitResponse.class);
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

    /**
     * Generate a map of non-null {@link String} keys and values
     *
     * @param keyValues Key-value tuples as vararg.
     * @return The map of non-null keys and values.
     */
    private static Map<String, String> mapOfStrings(Object... keyValues) {
        Map<String, String> map = new HashMap<>(keyValues.length / 2, 1);
        for (int i = 0; i < keyValues.length - 1; i = i + 2) {
            Object key = keyValues[i];
            Object val = keyValues[i + 1];
            if (key instanceof String keyStr && val != null) {
                map.put(keyStr, val.toString());
            }
        }

        return map;
    }

    /**
     * Generate a map of non-null {@link String} keys and {@link Object} values
     *
     * @param keyValues Key-value tuples as vararg.
     * @return The map of non-null keys and values.
     */
    private static Map<String, Object> mapOf(Object... keyValues) {
        Map<String, Object> map = new HashMap<>(keyValues.length / 2, 1);
        for (int i = 0; i < keyValues.length - 1; i = i + 2) {
            Object key = keyValues[i];
            Object val = keyValues[i + 1];
            if (key instanceof String keyStr && val != null) {
                map.put(keyStr, val);
            }
        }

        return map;
    }
}
