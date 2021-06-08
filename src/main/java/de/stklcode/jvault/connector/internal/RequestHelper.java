package de.stklcode.jvault.connector.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.response.ErrorResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Helper class to bundle Vault HTTP requests.
 *
 * @author Stefan Kalscheuer
 * @since 0.8 Extracted methods from {@link de.stklcode.jvault.connector.HTTPVaultConnector}.
 */
public final class RequestHelper implements Serializable {
    private static final String HEADER_VAULT_TOKEN = "X-Vault-Token";

    private final String baseURL;                   // Base URL of Vault.
    private final Integer timeout;                  // Timeout in milliseconds.
    private final int retries;                      // Number of retries on 5xx errors.
    private final String tlsVersion;                // TLS version (#22).
    private final X509Certificate trustedCaCert;    // Trusted CA certificate.
    private final ObjectMapper jsonMapper;

    /**
     * Constructor of the request helper.
     *
     * @param baseURL       The URL
     * @param retries       Number of retries on 5xx errors
     * @param timeout       Timeout for HTTP requests (milliseconds)
     * @param tlsVersion    TLS Version.
     * @param trustedCaCert Trusted CA certificate
     */
    public RequestHelper(final String baseURL,
                         final int retries,
                         final Integer timeout,
                         final String tlsVersion,
                         final X509Certificate trustedCaCert) {
        this.baseURL = baseURL;
        this.retries = retries;
        this.timeout = timeout;
        this.tlsVersion = tlsVersion;
        this.trustedCaCert = trustedCaCert;
        this.jsonMapper = new ObjectMapper();
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
        } catch (JsonProcessingException e) {
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
        } catch (IOException e) {
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
    public void postWithoutResponse(final String path, final Object payload, final String token) throws VaultConnectorException {
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
    public String put(final String path, final Map<String, String> payload, final String token) throws VaultConnectorException {
        // Initialize PUT.
        var req = HttpRequest.newBuilder(URI.create(baseURL + path));

        // Generate JSON from payload.
        try {
            req.PUT(HttpRequest.BodyPublishers.ofString(jsonMapper.writeValueAsString(payload), UTF_8));
        } catch (JsonProcessingException e) {
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
        } catch (IOException e) {
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
                    payload.entrySet().stream().map(
                            par -> URLEncoder.encode(par.getKey(), UTF_8) + "=" + URLEncoder.encode(par.getValue(), UTF_8)
                    ).collect(Collectors.joining("&"))
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
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
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

        var clientBuilder = HttpClient.newBuilder();

        // Set custom timeout, if defined.
        if (this.timeout != null) {
            clientBuilder.connectTimeout(Duration.ofMillis(timeout));
        }

        // Set custom SSL context.
        clientBuilder.sslContext(createSSLContext());

        HttpClient client = clientBuilder.build();

        // Execute request.
        try {
            HttpResponse<InputStream> response = client.sendAsync(
                    requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofInputStream()
            ).join();

            /* Check if response is valid */
            if (response == null) {
                throw new InvalidResponseException("Response unavailable");
            }

            switch (response.statusCode()) {
                case 200:
                    return handleResult(response);
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
        } catch (CompletionException e) {
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
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e) {
            throw new TlsException(Error.INIT_SSL_CONTEXT, e);
        }
    }

    /**
     * Handle successful result.
     *
     * @param response The raw HTTP response (assuming status code 200)
     * @return Complete response body as String
     * @throws InvalidResponseException on reading errors
     */
    private String handleResult(final HttpResponse<InputStream> response) throws InvalidResponseException {
        try (var reader = new BufferedReader(new InputStreamReader(response.body()))) {
            return reader.lines().collect(Collectors.joining("\n"));
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
    private void handleError(final HttpResponse<InputStream> response) throws VaultConnectorException {
        if (response.body() != null) {
            try (var reader = new BufferedReader(new InputStreamReader(response.body()))) {
                var responseString = reader.lines().collect(Collectors.joining("\n"));
                ErrorResponse er = jsonMapper.readValue(responseString, ErrorResponse.class);
                /* Check for "permission denied" response */
                if (!er.getErrors().isEmpty() && er.getErrors().get(0).equals("permission denied")) {
                    throw new PermissionDeniedException();
                }
                throw new InvalidResponseException(Error.RESPONSE_CODE, response.statusCode(), er.toString());
            } catch (IOException ignored) {
                // Exception ignored.
            }
        }
    }
}
