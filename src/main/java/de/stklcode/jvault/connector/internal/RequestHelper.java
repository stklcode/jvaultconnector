package de.stklcode.jvault.connector.internal;

import tools.jackson.core.JacksonException;

import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.response.ErrorResponse;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Helper class to bundle Vault HTTP requests.
 * <p>
 * A single {@link HttpClient} is created lazily on the first request and reused for all subsequent requests,
 * so connections and TLS sessions are pooled. It is released by {@link #close()}.
 *
 * @author Stefan Kalscheuer
 * @since 0.8 Extracted methods from {@link de.stklcode.jvault.connector.HTTPVaultConnector}.
 * @since 2.0.0 Reuse HTTP client, implements {@link AutoCloseable}
 */
public final class RequestHelper implements Serializable, AutoCloseable {
    private static final String HEADER_VAULT_TOKEN = "X-Vault-Token";

    private final String baseURL;                   // Base URL of Vault.
    private final Duration timeout;                 // Overall timeout per request attempt.
    private final Duration connectTimeout;          // Connect timeout.
    private final int retries;                     // Number of retries on 5xx errors.
    private final String tlsVersion;                // TLS version (#22).
    private final X509Certificate trustedCaCert;    // Trusted CA certificate.
    private final JsonMapper jsonMapper;

    private transient HttpClient client;            // HTTP client, created on first request.
    private transient boolean closed;               // Helper has been closed.

    /**
     * Constructor of the request helper.
     *
     * @param baseURL       The URL
     * @param retries       Number of retries on 5xx errors
     * @param timeout        Overall timeout per request attempt ({@code null} for no timeout)
     * @param connectTimeout Connect timeout ({@code null} to use the overall timeout)
     * @param tlsVersion     TLS Version.
     * @param trustedCaCert  Trusted CA certificate
     * @since 2.0.0 Timeouts as {@link Duration}, separate connect timeout
     */
    public RequestHelper(final String baseURL,
                         final int retries,
                         final Duration timeout,
                         final Duration connectTimeout,
                         final String tlsVersion,
                         final X509Certificate trustedCaCert) {
        this.baseURL = baseURL + (baseURL.endsWith("/") ? "" : "/");
        this.retries = retries;
        this.timeout = timeout;
        this.connectTimeout = connectTimeout != null ? connectTimeout : timeout;
        this.tlsVersion = tlsVersion;
        this.trustedCaCert = trustedCaCert;
        this.jsonMapper = JsonMapper.builder()
            .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DateTimeFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE)
            .disable(DateTimeFeature.WRITE_DATES_WITH_CONTEXT_TIME_ZONE)
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();
    }

    /**
     * Execute HTTP request using POST method.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String post(final String path, final Object payload, final String token) throws VaultConnectorException {
        // Initialize POST.
        var req = HttpRequest.newBuilder(URI.create(baseURL + path));

        // Generate JSON from payload.
        try {
            req.POST(HttpRequest.BodyPublishers.ofString(jsonMapper.writeValueAsString(payload), UTF_8));
        } catch (JacksonException e) {
            throw new InvalidRequestException(Error.PARSE_RESPONSE, e);
        }

        req.setHeader("Content-Type", "application/json; charset=utf-8");

        // Set X-Vault-Token header.
        if (token != null) {
            req.setHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(req, retries);
    }

    /**
     * Execute HTTP request using POST method and parse JSON result.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @param target  Target class.
     * @param <T>     Target type.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public <T> T post(final String path, final Object payload, final String token, final Class<T> target)
        throws VaultConnectorException {
        try {
            String response = post(path, payload, token);
            return jsonMapper.readValue(response, target);
        } catch (JacksonException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    /**
     * Execute HTTP request using POST method and expect empty (204) response.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public void postWithoutResponse(final String path, final Object payload, final String token)
        throws VaultConnectorException {
        if (!post(path, payload, token).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    /**
     * Execute HTTP request using PUT method.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String put(final String path, final Map<String, String> payload, final String token)
        throws VaultConnectorException {
        // Initialize PUT.
        var req = HttpRequest.newBuilder(URI.create(baseURL + path));

        // Generate JSON from payload.
        try {
            req.PUT(HttpRequest.BodyPublishers.ofString(jsonMapper.writeValueAsString(payload), UTF_8));
        } catch (JacksonException e) {
            throw new InvalidRequestException("Payload serialization failed", e);
        }

        req.setHeader("Content-Type", "application/json; charset=utf-8");

        // Set X-Vault-Token header.
        if (token != null) {
            req.setHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(req, retries);
    }

    /**
     * Execute HTTP request using PUT method and parse JSON result.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @param target  Target class.
     * @param <T>     Target type.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public <T> T put(final String path, final Map<String, String> payload, final String token, final Class<T> target)
        throws VaultConnectorException {
        try {
            String response = put(path, payload, token);
            return jsonMapper.readValue(response, target);
        } catch (JacksonException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    /**
     * Execute HTTP request using PUT method and expect empty (204) response.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public void putWithoutResponse(final String path, final Map<String, String> payload, final String token)
        throws VaultConnectorException {
        if (!put(path, payload, token).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    /**
     * Execute HTTP request using DELETE method.
     *
     * @param path  URL path (relative to base).
     * @param token Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String delete(final String path, final String token) throws VaultConnectorException {
        // Initialize DELETE.
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(baseURL + path)).DELETE();

        // Set X-Vault-Token header.
        if (token != null) {
            req.setHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(req, retries);
    }

    /**
     * Execute HTTP request using DELETE method and expect empty (204) response.
     *
     * @param path  URL path (relative to base).
     * @param token Vault token (may be {@code null}).
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public void deleteWithoutResponse(final String path, final String token) throws VaultConnectorException {
        if (!delete(path, token).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    /**
     * Execute HTTP request using GET method.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String get(final String path, final Map<String, String> payload, final String token)
        throws VaultConnectorException {
        // Add parameters to URI.
        var uriBuilder = new StringBuilder(baseURL + path);

        if (!payload.isEmpty()) {
            uriBuilder.append("?").append(
                payload.entrySet().stream()
                    .map(par -> encode(par.getKey()) + "=" + encode(par.getValue()))
                    .collect(Collectors.joining("&"))
            );
        }

        // Initialize GET.
        try {
            var req = HttpRequest.newBuilder(new URI(uriBuilder.toString()));

            // Set X-Vault-Token header.
            if (token != null) {
                req.setHeader(HEADER_VAULT_TOKEN, token);
            }

            return request(req, retries);
        } catch (URISyntaxException e) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }
    }

    /**
     * Execute HTTP request using GET method and parse JSON result to target class.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @param target  Target class.
     * @param <T>     Target type.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public <T> T get(final String path, final Map<String, String> payload, final String token, final Class<T> target)
        throws VaultConnectorException {
        try {
            String response = get(path, payload, token);
            return jsonMapper.readValue(response, target);
        } catch (JacksonException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    /**
     * Encode URL part.
     *
     * @param part Path part to URL-encode and insert into the template
     * @return Encoded URL part
     * @since 1.5.3
     */
    public static String encode(final String part) {
        return URLEncoder.encode(Objects.requireNonNullElse(part, ""), UTF_8);
    }

    /**
     * Execute prepared HTTP request and return result.
     *
     * @param requestBuilder Prepared request.
     * @param retries        Number of retries.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String request(final HttpRequest.Builder requestBuilder, final int retries) throws VaultConnectorException {
        // Set JSON Header.
        requestBuilder.setHeader("accept", "application/json");

        // Execute request.
        HttpResponse<String> response = send(client(), requestBuilder.build());

        /* Check if response is valid */
        if (response == null) {
            throw new InvalidResponseException("Response unavailable");
        }

        switch (response.statusCode()) {
            case 200:
                return Objects.requireNonNullElse(response.body(), "");
            case 204:
                return "";
            case 403:
                throw new PermissionDeniedException();
            default:
                if (response.statusCode() >= 500 && response.statusCode() < 600 && retries > 0) {
                    // Retry on 5xx errors.
                    return request(requestBuilder, retries - 1);
                } else {
                    // Fail on different error code and/or no retries left.
                    handleError(response);

                    // Throw exception without details, if response entity is empty.
                    throw new InvalidResponseException(Error.RESPONSE_CODE, response.statusCode());
                }
        }
    }

    /**
     * Get the HTTP client, create it on first use.
     * <p>
     * The client is not serialized, so a deserialized helper creates a new one.
     *
     * @return The HTTP client
     * @throws ConnectionException if the helper has been closed
     * @throws TlsException        if the SSL context could not be initialized
     * @since 2.0.0
     */
    private synchronized HttpClient client() throws VaultConnectorException {
        if (closed) {
            throw new ConnectionException(Error.CLOSED);
        }

        if (client == null) {
            var clientBuilder = HttpClient.newBuilder();

            // Set connect timeout, if defined.
            if (connectTimeout != null) {
                clientBuilder.connectTimeout(connectTimeout);
            }

            // Set custom SSL context.
            clientBuilder.sslContext(createSSLContext());

            client = clientBuilder.build();
        }

        return client;
    }

    /**
     * Close the helper and release the HTTP client.
     * <p>
     * Subsequent requests fail with a {@link ConnectionException}. Closing an already closed helper has no effect.
     * On Java 21 and later, this waits for running requests to complete.
     *
     * @since 2.0.0
     */
    @Override
    public void close() {
        HttpClient c;
        synchronized (this) {
            closed = true;
            c = client;
            client = null;
        }

        if (c instanceof AutoCloseable closeable) {
            // HttpClient is AutoCloseable since Java 21. Earlier versions release resources on garbage collection.
            try {
                closeable.close();
            } catch (Exception ignored) {
                // Ignore.
            }
        }
    }

    /**
     * Send the request and wait for the complete response, enforcing the overall timeout.
     * <p>
     * {@link HttpRequest.Builder#timeout(Duration)} only covers the time until response headers are received,
     * so the deadline is enforced on the response future, which completes after the body has been read.
     *
     * @param client  HTTP client.
     * @param request HTTP request.
     * @return HTTP response with body
     * @throws ConnectionException on connection errors, timeouts or interruption
     * @since 2.0.0
     */
    private HttpResponse<String> send(final HttpClient client, final HttpRequest request) throws ConnectionException {
        var future = client.sendAsync(request, HttpResponse.BodyHandlers.ofString(UTF_8));
        try {
            if (timeout != null) {
                return future.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
            } else {
                return future.get();
            }
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new ConnectionException(Error.TIMEOUT, e);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new ConnectionException(Error.CONNECTION, e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof HttpTimeoutException) {
                throw new ConnectionException(Error.TIMEOUT, e.getCause());
            }
            throw new ConnectionException(Error.CONNECTION, e.getCause());
        }
    }

    /**
     * Create a custom SSL context from trusted CA certificate.
     *
     * @return The context.
     * @throws TlsException An error occurred during initialization of the SSL context.
     * @since 0.8.0
     * @since 0.10 Generate {@link SSLContext} instead of Apache {@code SSLConnectionSocketFactory}
     */
    private SSLContext createSSLContext() throws TlsException {
        try {
            // Create context.
            var sslContext = SSLContext.getInstance(tlsVersion);

            if (trustedCaCert != null) {
                // Create Keystore with trusted certificate.
                var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                keyStore.setCertificateEntry("trustedCert", trustedCaCert);

                // Initialize TrustManager.
                var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keyStore);
                sslContext.init(null, tmf.getTrustManagers(), null);
            } else {
                sslContext.init(null, null, null);
            }

            return sslContext;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException |
                 KeyManagementException e) {
            throw new TlsException(Error.INIT_SSL_CONTEXT, e);
        }
    }

    /**
     * Handle unsuccessful response. Throw detailed exception if possible.
     *
     * @param response The raw HTTP response (assuming status code 5xx)
     * @throws VaultConnectorException Expected exception with details to throw
     */
    private void handleError(final HttpResponse<String> response) throws VaultConnectorException {
        var body = response.body();
        if (body == null || body.isBlank()) {
            return;
        }

        ErrorResponse er = null;
        try {
            er = jsonMapper.readValue(body, ErrorResponse.class);
        } catch (JacksonException ignored) {
            // Unparsable error body, fall back to generic exception.
        }

        /* Check for "permission denied" response */
        if (er != null && er.errors() != null && !er.errors().isEmpty() && er.errors().get(0).equals("permission denied")) {
            throw new PermissionDeniedException();
        }
        throw new InvalidResponseException(Error.RESPONSE_CODE, response.statusCode(), String.valueOf(er));
    }
}
